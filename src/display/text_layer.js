/* Copyright 2015 Mozilla Foundation
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

/** @typedef {import("./display_utils").PageViewport} PageViewport */
/** @typedef {import("./api").TextContent} TextContent */

import { AbortException, Util } from "../shared/util.js";
import { setLayerDimensions } from "./display_utils.js";

/**
 * Text layer render parameters.
 *
 * @typedef {Object} TextLayerRenderParameters
 * @property {ReadableStream | TextContent} textContentSource - Text content to
 *   render, i.e. the value returned by the page's `streamTextContent` or
 *   `getTextContent` method.
 * @property {HTMLElement} container - The DOM node that will contain the text
 *   runs.
 * @property {PageViewport} viewport - The target viewport to properly layout
 *   the text runs.
 * @property {Array<HTMLElement>} [textDivs] - HTML elements that correspond to
 *   the text items of the textContent input.
 *   This is output and shall initially be set to an empty array.
 * @property {WeakMap<HTMLElement,Object>} [textDivProperties] - Some properties
 *   weakly mapped to the HTML elements used to render the text.
 * @property {Array<string>} [textContentItemsStr] - Strings that correspond to
 *   the `str` property of the text items of the textContent input.
 *   This is output and shall initially be set to an empty array.
 */

/**
 * Text layer update parameters.
 *
 * @typedef {Object} TextLayerUpdateParameters
 * @property {HTMLElement} container - The DOM node that will contain the text
 *   runs.
 * @property {PageViewport} viewport - The target viewport to properly layout
 *   the text runs.
 * @property {Array<HTMLElement>} [textDivs] - HTML elements that correspond to
 *   the text items of the textContent input.
 *   This is output and shall initially be set to an empty array.
 * @property {WeakMap<HTMLElement,Object>} [textDivProperties] - Some properties
 *   weakly mapped to the HTML elements used to render the text.
 * @property {boolean} [mustRotate] true if the text layer must be rotated.
 * @property {boolean} [mustRescale] true if the text layer contents must be
 *   rescaled.
 */

const MAX_TEXT_DIVS_TO_RENDER = 100000;
const DEFAULT_FONT_SIZE = 30;
const DEFAULT_FONT_ASCENT = 0.8;
const ascentCache = new Map();
let _canvasContext = null;

function getCtx() {
  if (!_canvasContext) {
    // We don't use an OffscreenCanvas here because we use serif/sans serif
    // fonts with it and they depends on the locale.
    // In Firefox, the <html> element get a lang attribute that depends on what
    // Fluent returns for the locale and the OffscreenCanvas uses the OS locale.
    // Those two locales can be different and consequently the used fonts will
    // be different (see bug 1869001).
    // Ideally, we should use in the text layer the fonts we've in the pdf (or
    // their replacements when they aren't embedded) and then we can use an
    // OffscreenCanvas.
    const canvas = document.createElement("canvas");
    canvas.className = "hiddenCanvasElement";
    document.body.append(canvas);
    _canvasContext = canvas.getContext("2d", { alpha: false });
  }

  return _canvasContext;
}

function cleanupTextLayer() {
  _canvasContext?.canvas.remove();
  _canvasContext = null;
}

function getAscent(fontFamily) {
  const cachedAscent = ascentCache.get(fontFamily);
  if (cachedAscent) {
    return cachedAscent;
  }

  const ctx = getCtx();

  const savedFont = ctx.font;
  ctx.canvas.width = ctx.canvas.height = DEFAULT_FONT_SIZE;
  ctx.font = `${DEFAULT_FONT_SIZE}px ${fontFamily}`;
  const metrics = ctx.measureText("");

  // Both properties aren't available by default in Firefox.
  let ascent = metrics.fontBoundingBoxAscent;
  let descent = Math.abs(metrics.fontBoundingBoxDescent);
  if (ascent) {
    const ratio = ascent / (ascent + descent);
    ascentCache.set(fontFamily, ratio);

    ctx.canvas.width = ctx.canvas.height = 0;
    ctx.font = savedFont;
    return ratio;
  }

  // Try basic heuristic to guess ascent/descent.
  // Draw a g with baseline at 0,0 and then get the line
  // number where a pixel has non-null red component (starting
  // from bottom).
  ctx.strokeStyle = "red";
  ctx.clearRect(0, 0, DEFAULT_FONT_SIZE, DEFAULT_FONT_SIZE);
  ctx.strokeText("g", 0, 0);
  let pixels = ctx.getImageData(
    0,
    0,
    DEFAULT_FONT_SIZE,
    DEFAULT_FONT_SIZE
  ).data;
  descent = 0;
  for (let i = pixels.length - 1 - 3; i >= 0; i -= 4) {
    if (pixels[i] > 0) {
      descent = Math.ceil(i / 4 / DEFAULT_FONT_SIZE);
      break;
    }
  }

  // Draw an A with baseline at 0,DEFAULT_FONT_SIZE and then get the line
  // number where a pixel has non-null red component (starting
  // from top).
  ctx.clearRect(0, 0, DEFAULT_FONT_SIZE, DEFAULT_FONT_SIZE);
  ctx.strokeText("A", 0, DEFAULT_FONT_SIZE);
  pixels = ctx.getImageData(0, 0, DEFAULT_FONT_SIZE, DEFAULT_FONT_SIZE).data;
  ascent = 0;
  for (let i = 0, ii = pixels.length; i < ii; i += 4) {
    if (pixels[i] > 0) {
      ascent = DEFAULT_FONT_SIZE - Math.floor(i / 4 / DEFAULT_FONT_SIZE);
      break;
    }
  }

  ctx.canvas.width = ctx.canvas.height = 0;
  ctx.font = savedFont;

  if (ascent) {
    const ratio = ascent / (ascent + descent);
    ascentCache.set(fontFamily, ratio);
    return ratio;
  }

  ascentCache.set(fontFamily, DEFAULT_FONT_ASCENT);
  return DEFAULT_FONT_ASCENT;
}

function appendText(task, geom) {
  // Initialize all used properties to keep the caches monomorphic.
  const textDiv = document.createElement("span");
  const textDivProperties = {
    angle: 0,
    canvasWidth: 0,
    hasText: geom.str !== "",
    hasEOL: geom.hasEOL,
    fontSize: 0,
  };
  task._textDivs.push(textDiv);

  const tx = Util.transform(task._transform, geom.transform);
  let angle = Math.atan2(tx[1], tx[0]);
  const style = task._styleCache[geom.fontName];
  if (style.vertical) {
    angle += Math.PI / 2;
  }

  const fontFamily =
    (task._fontInspectorEnabled && style.fontSubstitution) || style.fontFamily;
  const fontHeight = Math.hypot(tx[2], tx[3]);
  const fontAscent = fontHeight * getAscent(fontFamily);

  let left, top;
  if (angle === 0) {
    left = tx[4];
    top = tx[5] - fontAscent;
  } else {
    left = tx[4] + fontAscent * Math.sin(angle);
    top = tx[5] - fontAscent * Math.cos(angle);
  }

  const scaleFactorStr = "calc(var(--scale-factor)*";
  const divStyle = textDiv.style;
  // Setting the style properties individually, rather than all at once,
  // should be OK since the `textDiv` isn't appended to the document yet.
  if (task._container === task._rootContainer) {
    divStyle.left = `${((100 * left) / task._pageWidth).toFixed(2)}%`;
    divStyle.top = `${((100 * top) / task._pageHeight).toFixed(2)}%`;
  } else {
    // We're in a marked content span, hence we can't use percents.
    divStyle.left = `${scaleFactorStr}${left.toFixed(2)}px)`;
    divStyle.top = `${scaleFactorStr}${top.toFixed(2)}px)`;
  }
  divStyle.fontSize = `${scaleFactorStr}${fontHeight.toFixed(2)}px)`;
  divStyle.fontFamily = fontFamily;

  textDivProperties.fontSize = fontHeight;

  // Keeps screen readers from pausing on every new text span.
  textDiv.setAttribute("role", "presentation");

  textDiv.textContent = geom.str;
  // geom.dir may be 'ttb' for vertical texts.
  textDiv.dir = geom.dir;

  // `fontName` is only used by the FontInspector, and we only use `dataset`
  // here to make the font name available in the debugger.
  if (task._fontInspectorEnabled) {
    textDiv.dataset.fontName =
      style.fontSubstitutionLoadedName || geom.fontName;
  }
  if (angle !== 0) {
    textDivProperties.angle = angle * (180 / Math.PI);
  }
  // We don't bother scaling single-char text divs, because it has very
  // little effect on text highlighting. This makes scrolling on docs with
  // lots of such divs a lot faster.
  let shouldScaleText = false;
  if (geom.str.length > 1) {
    shouldScaleText = true;
  } else if (geom.str !== " " && geom.transform[0] !== geom.transform[3]) {
    const absScaleX = Math.abs(geom.transform[0]),
      absScaleY = Math.abs(geom.transform[3]);
    // When the horizontal/vertical scaling differs significantly, also scale
    // even single-char text to improve highlighting (fixes issue11713.pdf).
    if (
      absScaleX !== absScaleY &&
      Math.max(absScaleX, absScaleY) / Math.min(absScaleX, absScaleY) > 1.5
    ) {
      shouldScaleText = true;
    }
  }
  if (shouldScaleText) {
    textDivProperties.canvasWidth = style.vertical ? geom.height : geom.width;
  }
  task._textDivProperties.set(textDiv, textDivProperties);
  task._layoutText(textDiv);
}

function layout(params) {
  const { div, scale, properties, ctx, prevFontSize, prevFontFamily } = params;
  const { style } = div;
  let transform = "";
  if (properties.canvasWidth !== 0 && properties.hasText) {
    const { fontFamily } = style;
    const { canvasWidth, fontSize } = properties;

    if (prevFontSize !== fontSize || prevFontFamily !== fontFamily) {
      ctx.font = `${fontSize * scale}px ${fontFamily}`;
      params.prevFontSize = fontSize;
      params.prevFontFamily = fontFamily;
    }

    // Only measure the width for multi-char text divs, see `appendText`.
    const { width } = ctx.measureText(div.textContent);

    if (width > 0) {
      transform = `scaleX(${(canvasWidth * scale) / width})`;
    }
  }
  if (properties.angle !== 0) {
    transform = `rotate(${properties.angle}deg) ${transform}`;
  }
  if (transform.length > 0) {
    style.transform = transform;
  }
}

function render(task) {
  if (task._canceled) {
    return;
  }
  const textDivs = task._textDivs;
  const capability = task._capability;
  const textDivsLength = textDivs.length;

  // No point in rendering many divs as it would make the browser
  // unusable even after the divs are rendered.
  if (textDivsLength > MAX_TEXT_DIVS_TO_RENDER) {
    capability.resolve();
    return;
  }
  capability.resolve();
}

class TextLayerRenderTask {
  #reader = null;

  #textContentSource = null;

  constructor({
    textContentSource,
    container,
    viewport,
    textDivs,
    textDivProperties,
    textContentItemsStr,
  }) {
    if (textContentSource instanceof ReadableStream) {
      this.#textContentSource = textContentSource;
    } else if (
      (typeof PDFJSDev === "undefined" || PDFJSDev.test("GENERIC")) &&
      typeof textContentSource === "object"
    ) {
      this.#textContentSource = new ReadableStream({
        start(controller) {
          controller.enqueue(textContentSource);
          controller.close();
        },
      });
    } else {
      throw new Error('No "textContentSource" parameter specified.');
    }
    this._container = this._rootContainer = container;
    this._textDivs = textDivs || [];
    this._textContentItemsStr = textContentItemsStr || [];
    this._fontInspectorEnabled = !!globalThis.FontInspector?.enabled;

    this._textDivProperties = textDivProperties || new WeakMap();
    this._canceled = false;
    this._capability = Promise.withResolvers();
    this._layoutTextParams = {
      prevFontSize: null,
      prevFontFamily: null,
      div: null,
      scale: viewport.scale * (globalThis.devicePixelRatio || 1),
      properties: null,
      ctx: getCtx(),
    };
    this._styleCache = Object.create(null);
    const { pageWidth, pageHeight, pageX, pageY } = viewport.rawDims;
    this._transform = [1, 0, 0, -1, -pageX, pageY + pageHeight];
    this._pageWidth = pageWidth;
    this._pageHeight = pageHeight;

    setLayerDimensions(container, viewport);

    // Always clean-up the temporary canvas once rendering is no longer pending.
    this._capability.promise
      .finally(() => {
        this._layoutTextParams = null;
        this._styleCache = null;
      })
      .catch(() => {
        // Avoid "Uncaught promise" messages in the console.
      });
  }

  /**
   * Promise for textLayer rendering task completion.
   * @type {Promise<void>}
   */
  get promise() {
    return this._capability.promise;
  }

  /**
   * Cancel rendering of the textLayer.
   */
  cancel() {
    this._canceled = true;
    const abortEx = new AbortException("TextLayer task cancelled.");

    this.#reader?.cancel(abortEx).catch(() => {
      // Avoid "Uncaught promise" messages in the console.
    });
    this.#reader = null;

    this._capability.reject(abortEx);
  }

  /**
   * @private
   */
  _processItems(items) {
    for (const item of items) {
      if (item.str === undefined) {
        if (
          item.type === "beginMarkedContentProps" ||
          item.type === "beginMarkedContent"
        ) {
          const parent = this._container;
          this._container = document.createElement("span");
          this._container.classList.add("markedContent");
          if (item.id !== null) {
            this._container.setAttribute("id", `${item.id}`);
          }
          parent.append(this._container);
        } else if (item.type === "endMarkedContent") {
          this._container = this._container.parentNode;
        }
        continue;
      }
      this._textContentItemsStr.push(item.str);
      appendText(this, item);
    }
  }

  /**
   * @private
   */
  _layoutText(textDiv) {
    const textDivProperties = (this._layoutTextParams.properties =
      this._textDivProperties.get(textDiv));
    this._layoutTextParams.div = textDiv;
    layout(this._layoutTextParams);

    if (textDivProperties.hasText) {
      this._container.append(textDiv);
    }
    if (textDivProperties.hasEOL) {
      const br = document.createElement("br");
      br.setAttribute("role", "presentation");
      this._container.append(br);
    }
  }

  /**
   * @private
   */
  _render() {
    const { promise, resolve, reject } = Promise.withResolvers();
    const styleCache = this._styleCache;

    const pump = () => {
      this.#reader.read().then(({ value, done }) => {
        if (done) {
          resolve();
          return;
        }

        Object.assign(styleCache, value.styles);
        this._processItems(value.items);
        pump();
      }, reject);
    };

    this.#reader = this.#textContentSource.getReader();
    pump();

    promise.then(() => {
      render(this);
    }, this._capability.reject);
  }
}

/**
 * @param {TextLayerRenderParameters} params
 * @returns {TextLayerRenderTask}
 */
function renderTextLayer(params) {
  const task = new TextLayerRenderTask(params);
  task._render();
  return task;
}

/**
 * @param {TextLayerUpdateParameters} params
 * @returns {undefined}
 */
function updateTextLayer({
  container,
  viewport,
  textDivs,
  textDivProperties,
  mustRotate = true,
  mustRescale = true,
}) {
  if (mustRotate) {
    setLayerDimensions(container, { rotation: viewport.rotation });
  }

  if (mustRescale) {
    const ctx = getCtx();
    const scale = viewport.scale * (globalThis.devicePixelRatio || 1);
    const params = {
      prevFontSize: null,
      prevFontFamily: null,
      div: null,
      scale,
      properties: null,
      ctx,
    };
    for (const div of textDivs) {
      params.properties = textDivProperties.get(div);
      params.div = div;
      layout(params);
    }
  }
}

export {
  cleanupTextLayer,
  renderTextLayer,
  TextLayerRenderTask,
  updateTextLayer,
};
