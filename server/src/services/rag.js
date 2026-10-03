const fs = require('fs/promises');
const path = require('path');
const { tryGetDb } = require('../db/mongo');
const { embedText } = require('../ai/gemini');
const { logger } = require('../logging/logger');

let localKnowledgePromise;

function wordsOf(value) {
  return String(value || '').toLowerCase().split(/\W+/).filter(word => word.length > 2);
}

async function localKnowledge() {
  if (!localKnowledgePromise) {
    const filePath = path.join(__dirname, '..', 'data', 'knowledge.json');
    localKnowledgePromise = fs.readFile(filePath, 'utf8').then(JSON.parse);
  }
  return localKnowledgePromise;
}

async function localSearch(query, limit) {
  const terms = new Set(wordsOf(query));
  const docs = await localKnowledge();
  return docs
    .map(doc => {
      const haystack = wordsOf(`${doc.title} ${doc.text}`);
      const score = haystack.reduce((total, word) => total + (terms.has(word) ? 1 : 0), 0);
      return { ...doc, score };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(({ score, ...doc }) => doc);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function retrieveKnowledge(query, limit = 4) {
  const db = await tryGetDb();
  if (!db) return localSearch(query, limit);

  try {
    const vector = await embedText(query);
    const matches = await db.collection('knowledge').aggregate([
      {
        $vectorSearch: {
          index: process.env.VECTOR_INDEX || 'knowledge_vector_index',
          path: 'embedding',
          queryVector: vector,
          numCandidates: 50,
          limit
        }
      },
      { $project: { _id: 0, title: 1, source: 1, text: 1, score: { $meta: "vectorSearchScore" } } }
    ]).toArray();
    if (matches.length > 0) return matches;
  } catch (error) {
    logger.warn('vector_search_unavailable', { message: error.message });
  }

  try {
    const words = wordsOf(query).slice(0, 8).map(escapeRegex);
    const matches = words.length === 0 ? [] : await db.collection('knowledge').find({
      $or: words.map(word => ({ text: { $regex: word, $options: 'i' } }))
    }).project({ _id: 0, title: 1, source: 1, text: 1 }).limit(limit).toArray();
    if (matches.length > 0) return matches;
  } catch (error) {
    logger.warn('mongodb_knowledge_search_failed', { message: error.message });
  }

  return localSearch(query, limit);
}

module.exports = { retrieveKnowledge, localSearch };
