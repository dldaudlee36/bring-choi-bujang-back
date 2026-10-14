// Approval belongs to the provided engine. No request header, installation
// flag, user role or login alone can supply a registered-device result.
export function createDeviceHandler({ requestApproval = false } = {}) {
  return async function deviceHandler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    const method = requestApproval ? 'POST' : 'GET';
    if (request.method !== method) {
      response.setHeader('Allow', method);
      return response.status(405).json({ error: 'Method not allowed' });
    }
    if (requestApproval) {
      // There is no engine registration endpoint/contract in this repository.
      // Do not record a request as accepted or grant access without that engine.
      return response.status(501).json({ approved: false, accepted: false,
        reason: 'device_approval_contract_unavailable' });
    }
    return response.status(200).json({ approved: false,
      reason: 'device_not_registered' });
  };
}
