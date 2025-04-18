/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';
import ClusterRoute from 'vault/mixins/cluster-route';
import ListRoute from 'core/mixins/list-route';

export default Route.extend(ClusterRoute, ListRoute, {
  store: service(),

  shouldReturnEmptyModel(policyType) {
    return policyType !== 'acl';
  },

  model(params) {
    const policyType = this.policyType();
    if (this.shouldReturnEmptyModel(policyType)) {
      return;
    }
    return this.store
      .lazyPaginatedQuery(`policy/${policyType}`, {
        page: params.page,
        pageFilter: params.pageFilter,
        responsePath: 'data.keys',
      })
      .catch((err) => {
        // acls will never be empty, but sentinel policies can be
        if (err.httpStatus === 404 && this.policyType() !== 'acl') {
          return [];
        } else {
          throw err;
        }
      });
  },

  setupController(controller, model) {
    const params = this.paramsFor(this.routeName);
    if (!model) {
      controller.setProperties({
        model: null,
        policyType: this.policyType(),
      });
      return;
    }
    controller.setProperties({
      model,
      filter: params.pageFilter || '',
      page: model.get('meta.currentPage') || 1,
      policyType: this.policyType(),
    });
  },

  resetController(controller, isExiting) {
    this._super(...arguments);
    if (isExiting) {
      controller.set('filter', '');
    }
  },

  actions: {
    willTransition(transition) {
      window.scrollTo(0, 0);
      if (!transition || transition.targetName !== this.routeName) {
        this.store.clearAllDatasets();
      }
      return true;
    },
    reload() {
      this.store.clearAllDatasets();
      this.refresh();
    },
  },

  policyType() {
    return this.paramsFor('vault.cluster.policies').type;
  },
});
