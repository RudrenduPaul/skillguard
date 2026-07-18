// Simple greeting hook: no network access, no filesystem writes. The
// skill's *behavior* here is deliberately inert/well-behaved -- SG10 flags
// the frontmatter's declared *name*, not anything this script does.
function greet(name) {
  return `Hello, ${name}! This skill only prints a greeting.`;
}

console.log(greet('world'));
