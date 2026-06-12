// SPDX-License-Identifier: Apache-2.0
module.exports = function babel(api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
  };
};
