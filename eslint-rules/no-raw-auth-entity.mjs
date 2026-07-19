// SPDX-License-Identifier: Apache-2.0

/**
 * Prevent the identity projection regression that caused self-approval risk.
 * `auth.entity` is a resolved entity row; authorization comparisons must use
 * the stable string returned by authEntityId(auth).
 */
const noRawAuthEntity = {
  meta: {
    type: 'problem',
    docs: {
      description: 'Disallow direct auth.entity access; use authEntityId(auth)',
    },
    schema: [],
    messages: {
      rawAuthEntity:
        'SECURITY: auth.entity is an entity row, not a caller identity. Use authEntityId(auth) for authorization comparisons.',
    },
  },

  create(context) {
    function isAuth(node) {
      return node?.type === 'Identifier' && node.name === 'auth';
    }

    function isEntityKey(node) {
      return node?.type === 'Identifier' && node.name === 'entity'
        || node?.type === 'Literal' && node.value === 'entity';
    }

    return {
      MemberExpression(node) {
        const objectIsAuth = isAuth(node.object);
        const propertyIsEntity = node.computed
          ? isEntityKey(node.property)
          : node.property?.type === 'Identifier' && node.property.name === 'entity';

        if (objectIsAuth && propertyIsEntity) {
          context.report({ node, messageId: 'rawAuthEntity' });
        }
      },

      VariableDeclarator(node) {
        if (!isAuth(node.init) || node.id?.type !== 'ObjectPattern') return;
        for (const property of node.id.properties) {
          if (property.type === 'Property' && isEntityKey(property.key)) {
            context.report({ node: property, messageId: 'rawAuthEntity' });
          }
        }
      },

      AssignmentExpression(node) {
        if (!isAuth(node.right) || node.left?.type !== 'ObjectPattern') return;
        for (const property of node.left.properties) {
          if (property.type === 'Property' && isEntityKey(property.key)) {
            context.report({ node: property, messageId: 'rawAuthEntity' });
          }
        }
      },
    };
  },
};

export default noRawAuthEntity;
