// Minimal DOM: just enough surface for web/app.js. It never parses markup, so a test can
// prove that hostile strings only ever end up as text nodes.
class Node {}
class Text extends Node {
  constructor(data) {
    super();
    this.data = data;
  }
  get textContent() {
    return this.data;
  }
}
class Element extends Node {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.attrs = {};
    this.children = [];
    this.listeners = {};
    this.value = "";
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  getAttribute(k) {
    return this.attrs[k] ?? null;
  }
  set className(v) {
    this.attrs.class = v;
  }
  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }
  append(...nodes) {
    for (const n of nodes) {
      if (!(n instanceof Node)) throw new Error("append of a non-Node: " + typeof n);
      this.children.push(n);
    }
  }
  replaceChildren(...nodes) {
    this.children = [];
    this.append(...nodes);
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  focus() {}
  get textContent() {
    return this.children.map((c) => c.textContent).join("");
  }
  find(tag) {
    const out = [];
    const walk = (n) => {
      if (n instanceof Element) {
        if (n.tagName === tag.toUpperCase()) out.push(n);
        n.children.forEach(walk);
      }
    };
    walk(this);
    return out;
  }
}
function install() {
  global.Node = Node;
  global.document = {
    createElement: (t) => new Element(t),
    createTextNode: (d) => new Text(String(d)),
    getElementById: () => new Element("div"),
  };
  const store = new Map();
  global.sessionStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  return { store };
}
module.exports = { install, Element, Text, Node };
