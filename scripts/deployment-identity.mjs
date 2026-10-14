const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

function validHttpsUrl(value, { allowQuery = false } = {}) {
  if (typeof value !== 'string' || value !== value.trim()) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === 'https:'
    && !url.username
    && !url.password
    && !url.hash
    && (allowQuery || !url.search);
}

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  const step = config?.step;

  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || ![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(step)
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || (step === 1 && (typeof config.sampleMarker !== 'string' || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)))
      || (step >= 3 && (!Array.isArray(config.allowedRoutes) || !config.allowedRoutes.length))
      || (step >= 5 && !validHttpsUrl(config.originalApiUrl))) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 현재 단계 설정을 확인하세요.');
  }

  const identity = {
    schema: 'aleph.defense.deployment.v1',
    step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
  };
  if (config.step === 1 && config.sampleMarker) {
    identity.sampleMarker = config.sampleMarker;
  }
  if (step >= 3 && config.identityProvider) {
    identity.identityProvider = config.identityProvider;
  }
  if (step >= 3 && Array.isArray(config.allowedRoutes) && config.allowedRoutes.length > 0) {
    identity.allowedRoutes = config.allowedRoutes;
  }
  if (step >= 5 && typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')) {
    identity.originalApiUrl = config.originalApiUrl;
  }
  if (step >= 10 && typeof config.restoreRoute === 'string' && config.restoreRoute) {
    identity.restoreRoute = config.restoreRoute;
  }
  return identity;
}
