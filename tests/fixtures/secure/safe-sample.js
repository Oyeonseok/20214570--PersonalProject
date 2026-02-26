element.textContent = userInput;
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
const hash = await bcrypt.hash(password, 12);
