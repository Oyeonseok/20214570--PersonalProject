const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query("DELETE FROM posts WHERE id = " + postId);
