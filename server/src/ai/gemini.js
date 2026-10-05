const { GoogleGenerativeAI } = require('@google/generative-ai');
const { logger } = require('../logging/logger');

function client() {
  if (!process.env.GEMINI_API_KEY) {
    const error = new Error('Gemini is not configured');
    error.code = 'GEMINI_UNAVAILABLE';
    throw error;
  }
  return new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
}

async function embedText(text) {
  const model = client().getGenerativeModel({ model: process.env.EMBEDDING_MODEL || 'gemini-embedding-001' });
  const result = await model.embedContent(text);
  return result.embedding.values;
}

function configuredModels() {
  const geminiModels = [
    process.env.GEMINI_MODEL || 'gemini-3.8-flash',
    ...(process.env.GEMINI_FALLBACK_MODELS || 'gemini-3.6-flash,gemini-3.5-flash-lite').split(',')
  ];
  const gemmaModels = [
    process.env.GEMMA_MODEL || 'gemma-4-26b-a4b-it',
    ...(process.env.GEMMA_FALLBACK_MODELS || 'gemma-4-31b-it').split(',')
  ];
  const provider = String(process.env.AI_PROVIDER || 'gemini').trim().toLowerCase();
  const ordered = provider === 'gemma'
    ? [...gemmaModels, ...geminiModels]
    : provider === 'auto'
      ? [gemmaModels[0], geminiModels[0], ...gemmaModels.slice(1), ...geminiModels.slice(1)]
      : [...geminiModels, ...gemmaModels];

  return ordered
    .map(name => name.trim())
    .filter((name, index, names) => name && names.indexOf(name) === index);
}

function parseJsonResponse(text) {
  const cleaned = String(text || '').trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(cleaned.slice(start, end + 1));
    throw new Error('AI model returned an invalid remediation response');
  }
}

async function generateRemediation({ finding, technologies, context }) {
  const prompt = `You are the remediation component of a defensive web-security assessment platform.\n\nRULES:\n- The scanner finding below is the source of truth.\n- Do not invent additional vulnerabilities.\n- Do not claim exploitation occurred.\n- If evidence is insufficient, explicitly say verification is required.\n- Use retrieved context when relevant.\n- Return JSON only.\n\nRequired JSON schema:\n{\n  "explanation": "string",\n  "whyItMatters": "string",\n  "remediation": "string",\n  "implementation": "string",\n  "verification": ["string"],\n  "confidence": "high|medium|low",\n  "limitations": "string"\n}\n\nFINDING:\n${JSON.stringify(finding)}\n\nDETECTED TECHNOLOGIES:\n${JSON.stringify(technologies || [])}\n\nRETRIEVED SECURITY GUIDANCE:\n${context || "No matching local guidance was retrieved."}`;

  const modelNames = configuredModels();

  let lastError;
  for (const modelName of modelNames) {
    try {
      const isGemma = modelName.startsWith('gemma-');
      const model = client().getGenerativeModel({
        model: modelName,
        generationConfig: isGemma
          ? { temperature: 0.2 }
          : { responseMimeType: 'application/json', temperature: 0.2 }
      });
      const result = await model.generateContent(prompt);
      return {
        ...parseJsonResponse(result.response.text()),
        model: modelName,
        provider: isGemma ? 'Gemma' : 'Gemini'
      };
    } catch (error) {
      lastError = error;
      logger.warn('gemini_model_failed', { model: modelName, message: error.message });
    }
  }

  throw lastError;
}

module.exports = { configuredModels, embedText, generateRemediation, parseJsonResponse };
