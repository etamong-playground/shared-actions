module.exports = async () => {
  const { inputs, configuration } = await import('./policy.mjs');
  const { addSecretForSanitizing } = await import('./runtime/node_modules/renovate/dist/util/sanitize.js');
  for (const value of [process.env.UPDATE_WRITER_TOKEN, process.env.UPDATE_SOURCE_TOKEN, process.env.UPDATE_PACKAGE_TOKEN].filter(Boolean)) {
    for (const secret of [value, encodeURIComponent(value), Buffer.from(value).toString('base64'), Buffer.from(`x-access-token:${value}`).toString('base64')]) addSecretForSanitizing(secret, 'global');
  }
  return configuration(inputs(process.env), JSON.parse(process.env.UPDATE_POLICY), JSON.parse(process.env.UPDATE_PREFLIGHT), process.env);
};
