const crypto = require('crypto');
const { tryGetDb } = require('../db/mongo');
const { retrieveKnowledge } = require('./rag');
const { generateRemediation } = require('../ai/gemini');
const { logger } = require('../logging/logger');

function cacheKey(finding, technologies) {
  return crypto.createHash("sha256")
    .update(JSON.stringify({ finding, technologies }))
    .digest("hex");
}

async function remediateFinding(finding, technologies = []) {
  const db = await tryGetDb();
  const key = cacheKey(finding, technologies);
  const cached = db ? await db.collection('remediationCache').findOne({ cacheKey: key }).catch(error => {
    logger.warn('remediation_cache_read_failed', { message: error.message });
    return null;
  }) : null;
  if (cached) return { ...cached.result, cached: true };

  const query = `${finding.name} ${finding.category || ""} ${finding.status || ""} ${technologies.map(t => typeof t === "string" ? t : t.name).join(" ")}`;
  const docs = await retrieveKnowledge(query);
  const context = docs.map((d, i) => `[${i + 1}] ${d.title}\n${d.text}\nSource: ${d.source}`).join("\n\n");
  const ai = await generateRemediation({ finding, technologies, context });
  const result = {
    ...ai,
    sources: docs.map(d => ({ title: d.title, source: d.source })),
    cached: false
  };
  if (db) {
    await db.collection('remediationCache').updateOne(
      { cacheKey: key },
      { $set: { cacheKey: key, result, createdAt: new Date() } },
      { upsert: true }
    ).catch(error => logger.warn('remediation_cache_write_failed', { message: error.message }));
  }
  return result;
}

module.exports = { remediateFinding };
