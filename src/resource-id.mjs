const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// The server route chooses the namespace; never accept a client resourceId or role.
export function resourceId(namespace, id = null) {
  if (!['notes', 'notices'].includes(namespace)) throw new TypeError('invalid_resource_namespace');
  if (id === null) return `${namespace}:collection`;
  if (typeof id !== 'string' || !UUID.test(id)) throw new TypeError('invalid_resource_id');
  return `${namespace}:${id.toLowerCase()}`;
}
