/* Copyright 2021 Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { removeNullCharacters } from "./ui_utils.js";

const PDF_ROLE_TO_HTML_ROLE = {
  // Document level structure types
  Document: null, // There's a "document" role, but it doesn't make sense here.
  DocumentFragment: null,
  // Grouping level structure types
  Part: "group",
  Sect: "group", // XXX: There's a "section" role, but it's abstract.
  Div: "group",
  Aside: "note",
  NonStruct: "none",
  // Block level structure types
  P: null,
  // H<n>,
  H: "heading",
  Title: null,
  FENote: "note",
  // Sub-block level structure type
  Sub: "group",
  // General inline level structure types
  Lbl: null,
  Span: null,
  Em: null,
  Strong: null,
  Link: "link",
  Annot: "note",
  Form: "form",
  // Ruby and Warichu structure types
  Ruby: null,
  RB: null,
  RT: null,
  RP: null,
  Warichu: null,
  WT: null,
  WP: null,
  // List standard structure types
  L: "list",
  LI: "listitem",
  LBody: null,
  // Table standard structure types
  Table: "table",
  TR: "row",
  TH: "columnheader",
  TD: "cell",
  THead: "columnheader",
  TBody: null,
  TFoot: null,
  // Standard structure type Caption
  Caption: null,
  // Standard structure type Figure
  Figure: "figure",
  // Standard structure type Formula
  Formula: null,
  // standard structure type Artifact
  Artifact: null,
};

const HEADING_PATTERN = /^H(\d+)$/;

class StructTreeLayerBuilder {
  #promise;

  #treeDom = undefined;

  #elementAttributes = new Map();

  constructor(pdfPage) {
    this.#promise = pdfPage.getStructTree();
  }

  async render() {
    if (this.#treeDom !== undefined) {
      return this.#treeDom;
    }
    const treeDom = (this.#treeDom = this.#walk(await this.#promise));
    this.#promise = null;
    treeDom?.classList.add("structTree");
    return treeDom;
  }

  async getAriaAttributes(annotationId) {
    await this.render();
    return this.#elementAttributes.get(annotationId);
  }

  hide() {
    if (this.#treeDom && !this.#treeDom.hidden) {
      this.#treeDom.hidden = true;
    }
  }

  show() {
    if (this.#treeDom?.hidden) {
      this.#treeDom.hidden = false;
    }
  }

  #setAttributes(structElement, htmlElement) {
    const { alt, id, lang } = structElement;
    if (alt !== undefined) {
      // Don't add the label in the struct tree layer but on the annotation
      // in the annotation layer.
      let added = false;
      const label = removeNullCharacters(alt);
      for (const child of structElement.children) {
        if (child.type === "annotation") {
          let attrs = this.#elementAttributes.get(child.id);
          if (!attrs) {
            attrs = new Map();
            this.#elementAttributes.set(child.id, attrs);
          }
          attrs.set("aria-label", label);
          added = true;
        }
      }
      if (!added) {
        htmlElement.setAttribute("aria-label", label);
      }
    }
    if (id !== undefined) {
      htmlElement.setAttribute("aria-owns", id);
    }
    if (lang !== undefined) {
      htmlElement.setAttribute(
        "lang",
        removeNullCharacters(lang, /* replaceInvisible = */ true)
      );
    }
  }

  #walk(node) {
    if (!node) {
      return null;
    }

    const element = document.createElement("span");
    if ("role" in node) {
      const { role } = node;
      const match = role.match(HEADING_PATTERN);
      if (match) {
        element.setAttribute("role", "heading");
        element.setAttribute("aria-level", match[1]);
      } else if (PDF_ROLE_TO_HTML_ROLE[role]) {
        element.setAttribute("role", PDF_ROLE_TO_HTML_ROLE[role]);
      }
    }

    this.#setAttributes(node, element);

    if (node.children) {
      if (node.children.length === 1 && "id" in node.children[0]) {
        // Often there is only one content node so just set the values on the
        // parent node to avoid creating an extra span.
        this.#setAttributes(node.children[0], element);
      } else {
        for (const kid of node.children) {
          element.append(this.#walk(kid));
        }
      }
    }
    return element;
  }
}

export { StructTreeLayerBuilder };
