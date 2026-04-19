import bcrypt from "bcrypt";
const hash = "$2a$12$IBiu4mY20oQIcnlDxqZRqeSnCvIAlh4kANrLIVSvQl9ovDYHX3ADe";
const pwd  = "medloop@&2026";
console.log("password length:", pwd.length, "bytes:", Buffer.from(pwd).toString('hex'));
const ok = await bcrypt.compare(pwd, hash);
console.log("bcrypt.compare:", ok);
const newHash = await bcrypt.hash(pwd, 12);
console.log("new hash:", newHash);
console.log("compare new:", await bcrypt.compare(pwd, newHash));
