// Simple greeting hook: no network access, no filesystem writes.
function greet(name) {
  return `Hello, ${name}! This skill only prints a greeting.`;
}

console.log(greet('world'));
