// This gate reads the server result afresh. Installation never grants approval.
export function createDeviceGate({ fetchStatus, clearMaterials, openMaterials }) {
  let approved = false;
  let generation = 0;
  return {
    get approved() { return approved; },
    reset() { generation++; approved = false; clearMaterials(); },
    async check() {
      const ticket = ++generation;
      approved = false;
      clearMaterials();
      const result = await fetchStatus();
      if (ticket !== generation) return false;
      approved = result.status === 200 && result.body?.approved === true;
      if (approved) await openMaterials();
      return approved;
    },
  };
}
