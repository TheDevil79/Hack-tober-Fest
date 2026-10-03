require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const { getDb, closeDb } = require('./db/mongo');
const { embedText } = require('./ai/gemini');

async function seedKnowledge() {
  const file = path.join(__dirname, 'data', 'knowledge.json');
  const docs = JSON.parse(await fs.readFile(file, 'utf8'));
  const db = await getDb();

  for (const doc of docs) {
    const embedding = await embedText(`${doc.title}\n${doc.text}`);
    await db.collection('knowledge').updateOne(
      { title: doc.title, source: doc.source },
      { $set: { ...doc, embedding, updatedAt: new Date() } },
      { upsert: true }
    );
    console.log('Seeded:', doc.title);
  }

  console.log('Knowledge seeding complete. Configure an Atlas Vector Search index on knowledge.embedding if desired.');
}

seedKnowledge()
  .then(() => closeDb())
  .catch(error => {
    console.error(`Knowledge seeding failed: ${error.message}`);
    process.exitCode = 1;
  });
