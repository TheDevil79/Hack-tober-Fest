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

async function generateRemediation({ finding, technologies, context }) {
  const prompt = `You are the remediation component of a defensive web-security assessment platform.\n\nRULES:\n- The scanner finding below is the source of truth.\n- Do not invent additional vulnerabilities.\n- Do not claim exploitation occurred.\n- If evidence is insufficient, explicitly say verification is required.\n- Use retrieved context when relevant.\n- Return JSON only.\n\nRequired JSON schema:\n{\n  "explanation": "string",\n  "whyItMatters": "string",\n  "remediation": "string",\n  "implementation": "string",\n  "verification": ["string"],\n  "confidence": "high|medium|low",\n  "limitations": "string"\n}\n\nFINDING:\n${JSON.stringify(finding)}\n\nDETECTED TECHNOLOGIES:\n${JSON.stringify(technologies || [])}\n\nRETRIEVED SECURITY GUIDANCE:\n${context || "No matching local guidance was retrieved."}`;

  const modelNames = [
    process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    ...(process.env.GEMINI_FALLBACK_MODELS || '')
      .split(',')
      .map(name => name.trim())
      .filter(Boolean)
  ].filter((name, index, names) => names.indexOf(name) === index);

  let lastError;
  for (const modelName of modelNames) {
    try {
      const model = client().getGenerativeModel({
        model: modelName,
        generationConfig: { responseMimeType: "application/json", temperature: 0.2 }
      });
      const result = await model.generateContent(prompt);
      return JSON.parse(result.response.text());
    } catch (error) {
      lastError = error;
      logger.warn('gemini_model_failed', { model: modelName, message: error.message });
    }
  }

  throw lastError;
}

module.exports = { embedText, generateRemediation };
