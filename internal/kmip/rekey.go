// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// rekey replaces the symmetric key uid, the predecessor P, with a new
// transit key, the successor S, and returns S's UID. S is the next
// generation of P's Name: with A the Name's anchor, its first generation,
// and g P's generation, S is A.<g+1>.
//
// Every step is safe to repeat, so a client that retries an interrupted
// ReKey resumes it:
//
//  1. Read P. Refuse a replaced or non-symmetric key. Refuse a
//     soft-deleted key too, unless it is the predecessor of a committed
//     ReKey that the retention sweep reached before step 7 linked it:
//     then only write that link.
//  2. Take A and g from P's record; a key without one is A itself, g=1.
//  3. Read S. When S is missing, mark it as P's pending_successor, then
//     create it. When S's record links back to P, resume and keep that
//     record: S may be committed and changed since. When S has no record
//     and P's marker names it, adopt it: an earlier attempt created it and
//     stopped. Any other S is a foreign key: fail and write nothing.
//  4. Unless S has its record, write it in one request, each entry
//     replaced whole. The write changes nothing when another ReKey wrote
//     the record after step 3.
//  5. Clear P's marker.
//  6. Commit: claim current=S on A, expecting P. Two ReKeys of one Name
//     cannot both win, and the Name never moves back to an older object.
//     A Name that holds a later generation than S held S before, so an
//     earlier attempt committed: go on to the link.
//  7. Link P to S. A retry after the commit and before this link repairs
//     it, also when the Name has moved on since.
//  8. Soft-delete the generations beyond kmip_rekey_retain, best effort.
func (c *call) rekey(ctx context.Context, uid string, offset *time.Duration, template *kmiplib.TemplateAttribute) (string, error) {
	if offset != nil && *offset != 0 {
		return "", kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "ReKey with an Offset is not supported")
	}

	pred, err := c.readKey(ctx, uid)
	if err != nil {
		return "", err
	}
	if pred.SoftDeleted {
		return c.repairSweptLink(ctx, uid, pred)
	}
	if next := pred.replacement(); next != "" {
		return "", kmipserver.Errorf(
			kmiplib.ResultReasonPermissionDenied,
			"wrong key lifecycle state: object %q is Deactivated: ReKey replaced it with %q", uid, next,
		)
	}
	alg, bitlen, objType, err := pred.kmipAttrs()
	if err != nil {
		return "", err
	}
	if objType != kmiplib.ObjectTypeSymmetricKey {
		return "", kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"ReKey replaces symmetric keys only; %q is a %s", uid, ttlv.EnumStr(objType),
		)
	}
	keyType, keySize, err := transitKeyType(alg, bitlen)
	if err != nil {
		return "", err
	}
	entries, err := templateEntries(uid, pred, template)
	if err != nil {
		return "", err
	}

	anchor, gen, succ, err := successorOf(uid, pred)
	if err != nil {
		return "", err
	}

	marked := pred.single(entryPending) == succ
	existing, err := c.lookupKey(ctx, succ)
	if err != nil {
		return "", err
	}
	if existing != nil && len(existing.Metadata[metadataScope]) == 0 && !marked {
		// A concurrent ReKey of P may have marked and created S after this
		// one read P. It writes the marker before the create and clears it
		// only after S's record, so read P and then S again before calling
		// S foreign: one of the two then shows S as that ReKey's.
		fresh, err := c.readKey(ctx, uid)
		if err != nil {
			return "", err
		}
		if marked = fresh.single(entryPending) == succ; !marked {
			if existing, err = c.lookupKey(ctx, succ); err != nil {
				return "", err
			}
		}
	}
	initialized := false
	switch {
	case existing == nil:
		// The marker lets a retry adopt S when this ReKey stops after
		// creating S and before writing its record. It leaves one race: an
		// operator who creates exactly S between this write and the create
		// below gets that key adopted as the replacement, because transit
		// answers a create of an existing key with that key.
		if _, err := c.writeMetadata(ctx, uid, claimOp(entryPending, succ, "")); err != nil {
			return "", err
		}
		marked = true
		if rep, err := c.createKey(ctx, succ, keyType, keySize); err != nil {
			// A 4xx answer means transit refused the create, so S does not
			// exist. Clear the marker, or a key created under S's name at any
			// later time would be adopted, not only one made in the window
			// above. Any other failure, a 5xx or a lost answer, may hide a
			// create that applied: keep the marker so a retry adopts S.
			if rep != nil && rep.status >= 400 && rep.status < 500 {
				if _, clearErr := c.writeMetadata(ctx, uid, deleteOp(entryPending)); clearErr != nil {
					c.s.t.logger.Warn("KMIP ReKey could not clear its pending successor", "key", uid, "successor", succ, "error", clearErr)
				}
			}
			return "", err
		}
	case existing.single(linkEntry(kmiplib.LinkTypeReplacedObjectLink)) == uid:
		// An earlier attempt wrote S's record: resume, and do not write it
		// again, or attributes added to S since would be lost.
		initialized = true
	case len(existing.Metadata[metadataScope]) == 0 && marked && existing.Type == keyType:
		// An earlier attempt created S and stopped before its record. A key
		// of another type under that name is not one this ReKey made.
	default:
		return "", errForeignSuccessor(uid, succ)
	}

	if !initialized {
		// The replacement takes the stored attributes, with the template's
		// replacing them, so ActivationDate and DeactivationDate carry over.
		record := pred.storedEntries()
		maps.Copy(record, entries)
		record[entryAnchor] = []string{anchor}
		record[entryGeneration] = []string{strconv.Itoa(gen + 1)}
		record[linkEntry(kmiplib.LinkTypeReplacedObjectLink)] = []string{uid}
		if err := c.writeSuccessorRecord(ctx, uid, succ, record); err != nil {
			return "", err
		}
	}

	if marked {
		if _, err := c.writeMetadata(ctx, uid, deleteOp(entryPending)); err != nil {
			return "", err
		}
	}

	committed, err := c.writeMetadata(ctx, anchor, claimOp(entryCurrent, succ, uid))
	switch {
	case err == nil:
	case claimLost(committed):
		moved, readErr := c.movedPast(ctx, anchor, gen+1)
		if readErr != nil {
			return "", readErr
		}
		if !moved {
			return "", kmipserver.Errorf(
				kmiplib.ResultReasonPermissionDenied,
				"wrong key lifecycle state: object %q is no longer the current object of the Name %q: %s", uid, anchor, committed.message(),
			)
		}
		// An earlier attempt committed and stopped before the link, and a
		// ReKey of S followed. That ReKey also ran the sweep.
		committed = nil
	default:
		return "", err
	}

	if _, err := c.writeMetadata(ctx, uid, linkOp(linkEntry(kmiplib.LinkTypeReplacementObjectLink), succ)); err != nil {
		return "", err
	}

	if committed != nil {
		c.sweep(ctx, anchor, gen+1, committed)
	}
	return succ, nil
}

// successorOf returns the anchor A of uid's Name, uid's generation g, and the
// UID A.<g+1> that uid's replacement takes. A key without an anchor is A
// itself, generation 1.
func successorOf(uid string, pred *keyInfo) (anchor string, gen int, succ string, err error) {
	anchor, gen = uid, 1
	if a := pred.single(entryAnchor); a != "" {
		anchor = a
		gen, err = strconv.Atoi(pred.single(entryGeneration))
		if err != nil || gen < 2 {
			return "", 0, "", kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "object %q has the anchor %q but no valid generation", uid, a)
		}
	}
	succ = anchor + "." + strconv.Itoa(gen+1)
	if err := checkName(succ); err != nil {
		return "", 0, "", err
	}
	return anchor, gen, succ, nil
}

// repairSweptLink finishes a ReKey of the soft-deleted key uid, or refuses.
// With kmip_rekey_retain=2, a ReKey of P can commit S and stop before it
// links P to S; a ReKey of S then sweeps P. P is soft-deleted but still has
// no ReplacementObjectLink, so a client holding P's UID cannot find S.
//
// The repair writes only that link. It runs only when S links back to P and
// the Name has moved to S or later, which together prove the earlier ReKey
// committed: nothing is created, the Name does not move, nothing is swept.
// Every other ReKey of a soft-deleted key is refused, as a revoked key must
// not be replaced.
func (c *call) repairSweptLink(ctx context.Context, uid string, pred *keyInfo) (string, error) {
	if pred.replacement() != "" {
		return "", errSoftDeleted(uid)
	}
	anchor, gen, succ, err := successorOf(uid, pred)
	if err != nil {
		return "", err
	}
	existing, err := c.lookupKey(ctx, succ)
	if err != nil {
		return "", err
	}
	if existing == nil || existing.single(linkEntry(kmiplib.LinkTypeReplacedObjectLink)) != uid {
		return "", errSoftDeleted(uid)
	}
	moved, err := c.movedPast(ctx, anchor, gen)
	if err != nil {
		return "", err
	}
	if !moved {
		return "", errSoftDeleted(uid)
	}
	if _, err := c.writeMetadata(ctx, uid, linkOp(linkEntry(kmiplib.LinkTypeReplacementObjectLink), succ)); err != nil {
		return "", err
	}
	return succ, nil
}

// writeSuccessorRecord writes the record of succ, the replacement of uid,
// in one request. The first operation fails the request when succ already
// has a record: no generation is 0, so the claim succeeds only on an absent
// entry. When a concurrent ReKey wrote the record first, this one keeps
// that record and the attributes added to it since.
func (c *call) writeSuccessorRecord(ctx context.Context, uid, succ string, record map[string][]string) error {
	ops := []metadataOp{claimOp(entryGeneration, "0", "")}
	for _, entry := range slices.Sorted(maps.Keys(record)) {
		ops = append(ops, replaceOps(entry, record[entry]...)...)
	}
	rep, err := c.writeMetadata(ctx, succ, ops...)
	if !claimLost(rep) {
		return err
	}

	existing, err := c.readKey(ctx, succ)
	if err != nil {
		return err
	}
	if existing.single(linkEntry(kmiplib.LinkTypeReplacedObjectLink)) != uid {
		return errForeignSuccessor(uid, succ)
	}
	return nil
}

// movedPast reports whether the Name of anchor holds a generation newer
// than gen. The Name moves only to the next generation, expecting the one
// before it, so it then held every generation up to gen.
func (c *call) movedPast(ctx context.Context, anchor string, gen int) (bool, error) {
	info, err := c.readKey(ctx, anchor)
	if err != nil {
		return false, err
	}
	suffix, ok := strings.CutPrefix(info.single(entryCurrent), anchor+".")
	if !ok {
		return false, nil
	}
	current, err := strconv.Atoi(suffix)
	return err == nil && current > gen, nil
}

func errForeignSuccessor(uid, succ string) error {
	return kmipserver.Errorf(
		kmiplib.ResultReasonGeneralFailure,
		"ReKey of %q must create the key %q, which already exists and is not its replacement: retry the ReKey, and if this error repeats, rename or delete %q", uid, succ, succ,
	)
}

// sweep soft-deletes the generations of a Name older than the newest
// kmip_rekey_retain, oldest first, and records on the anchor how far it
// got. The anchor keeps its record when its material goes, so the Name
// still resolves.
//
// It runs after the commit, so it never fails the ReKey: the client would
// be told the rotation failed when it succeeded. A generation it cannot
// soft-delete stays readable, and the next ReKey of the Name tries again.
func (c *call) sweep(ctx context.Context, anchor string, newest int, anchorRep *reply) {
	logger := c.s.t.logger

	retain, err := c.s.rekeyRetain(ctx)
	if err != nil {
		logger.Warn("KMIP ReKey skipped its retention sweep", "anchor", anchor, "error", err)
		return
	}

	var record struct {
		Metadata map[string]map[string][]string `json:"metadata"`
	}
	if err := anchorRep.decode(&record); err != nil {
		logger.Warn("KMIP ReKey skipped its retention sweep", "anchor", anchor, "error", err)
		return
	}
	swept := 0
	if values := record.Metadata[metadataScope][entrySwept]; len(values) == 1 {
		swept, _ = strconv.Atoi(values[0])
	}

	last := swept
	for g := swept + 1; g <= newest-retain; g++ {
		uid := anchor
		if g > 1 {
			uid = anchor + "." + strconv.Itoa(g)
		}
		r := request{method: http.MethodDelete, path: "keys/" + uid + "/soft-delete", capability: "delete"}
		rep, err := c.try(ctx, r)
		path := r.path
		if err == nil {
			path = rep.path
			if !rep.ok() {
				err = rep.failure()
			}
		}
		if err != nil {
			logger.Warn(
				"KMIP ReKey left an old generation readable: soft-deleting it failed, and the next ReKey of this Name tries again",
				"path", path, "capability", r.capability, "error", err,
			)
			break
		}
		last = g
	}

	if last > swept {
		if _, err := c.writeMetadata(ctx, anchor, replaceOps(entrySwept, strconv.Itoa(last))...); err != nil {
			logger.Warn("KMIP ReKey could not record its retention sweep", "anchor", anchor, "error", err)
		}
	}
}
