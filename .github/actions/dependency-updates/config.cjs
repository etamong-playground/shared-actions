module.exports = async () => {
  const { inputs, configuration } = await import('./policy.mjs');
  return configuration(inputs(process.env), JSON.parse(process.env.UPDATE_POLICY), JSON.parse(process.env.UPDATE_PREFLIGHT), process.env);
};
