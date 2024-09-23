/*
 * Copyright 2014 Mozilla Foundation
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

// PLEASE NOTE: This code is intended for development purposes only and
//              should NOT be used in production environments.

import fs from "fs";
import fsPromises from "fs/promises";
import http from "http";
import path from "path";
import { pathToFileURL } from "url";

const MIME_TYPES = {
  ".css": "text/css",
  ".html": "text/html",
  ".js": "application/javascript",
  ".mjs": "application/javascript",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf",
  ".xhtml": "application/xhtml+xml",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".log": "text/plain",
  ".bcmap": "application/octet-stream",
  ".ftl": "text/plain",
};
const DEFAULT_MIME_TYPE = "application/octet-stream";

class WebServer {
  constructor({ root, host, port, cacheExpirationTime }) {
    const cwdURL = pathToFileURL(process.cwd()) + "/";
    this.rootURL = new URL(`${root || "."}/`, cwdURL);
    this.host = host || "localhost";
    this.port = port || 0;
    this.server = null;
    this.verbose = false;
    this.cacheExpirationTime = cacheExpirationTime || 0;
    this.disableRangeRequests = false;
    this.hooks = {
      GET: [crossOriginHandler],
      POST: [],
    };
  }

  start(callback) {
    this.#ensureNonZeroPort();
    this.server = http.createServer(this.#handler.bind(this));
    this.server.listen(this.port, this.host, callback);
    console.log(`Server running at http://${this.host}:${this.port}/`);
  }

  stop(callback) {
    this.server.close(callback);
    this.server = null;
  }

  #ensureNonZeroPort() {
    if (!this.port) {
      // If port is 0, a random port will be chosen instead. Do not set a host
      // name to make sure that the port is synchronously set by `.listen()`.
      const server = http.createServer().listen(0);
      const address = server.address();
      // `.address().port` being available synchronously is merely an
      // implementation detail, so we are defensive here and fall back to a
      // fixed port when the address is not available yet.
      this.port = address ? address.port : 8000;
      server.close();
    }
  }

  async #handler(request, response) {
    // URLs are normalized and automatically disallow directory traversal
    // attacks. For example, http://HOST:PORT/../../../../../../../etc/passwd
    // is equivalent to http://HOST:PORT/etc/passwd.
    const url = new URL(`http://${this.host}:${this.port}${request.url}`);

    // Validate the request method and execute method hooks.
    const methodHooks = this.hooks[request.method];
    if (!methodHooks) {
      response.writeHead(405);
      response.end("Unsupported request method", "utf8");
      return;
    }
    const handled = methodHooks.some(hook => hook(url, request, response));
    if (handled) {
      return;
    }

    // Check the request and serve the file/folder contents.
    if (url.pathname === "/favicon.ico") {
      url.pathname = "/test/resources/favicon.ico";
    }
    await this.#checkRequest(request, response, url);
  }

  async #checkRequest(request, response, url) {
    const localURL = new URL(`.${url.pathname}`, this.rootURL);

    // Check if the file/folder exists.
    try {
      await fsPromises.realpath(localURL);
    } catch (e) {
      if (e instanceof URIError) {
        // If the URI cannot be decoded, a `URIError` is thrown. This happens
        // for malformed URIs such as `http://localhost:8888/%s%s` and should be
        // handled as a bad request.
        response.writeHead(400);
        response.end("Bad request", "utf8");
        return;
      }

      response.writeHead(404);
      response.end();
      if (this.verbose) {
        console.error(`${url}: not found`);
      }
      return;
    }

    // Get the properties of the file/folder.
    let stats;
    try {
      stats = await fsPromises.stat(localURL);
    } catch {
      response.writeHead(500);
      response.end();
      return;
    }
    const fileSize = stats.size;
    const isDir = stats.isDirectory();

    // If a folder is requested, serve the directory listing.
    if (isDir && !/\/$/.test(url.pathname)) {
      response.setHeader("Location", `${url.pathname}/${url.search}`);
      response.writeHead(301);
      response.end("Redirected", "utf8");
      return;
    }
    if (isDir) {
      await this.#serveDirectoryIndex(response, url, localURL);
      return;
    }

    // If a file is requested with range requests, serve it accordingly.
    const { range } = request.headers;
    if (range && !this.disableRangeRequests) {
      const rangesMatches = /^bytes=(\d+)-(\d+)?/.exec(range);
      if (!rangesMatches) {
        response.writeHead(501);
        response.end("Bad range", "utf8");
        if (this.verbose) {
          console.error(`${url}: bad range: ${range}`);
        }
        return;
      }

      const start = +rangesMatches[1];
      const end = +rangesMatches[2];
      if (this.verbose) {
        console.log(`${url}: range ${start}-${end}`);
      }
      this.#serveFileRange(
        response,
        localURL,
        fileSize,
        start,
        isNaN(end) ? fileSize : end + 1
      );
      return;
    }

    // Otherwise, serve the file normally.
    if (this.verbose) {
      console.log(url);
    }
    this.#serveFile(response, localURL, fileSize);
  }

  

  async #serveDirectoryIndex(response, url, localUrl) {
    response.setHeader("Content-Type", "text/html");
    response.writeHead(200);
    
    // IF NO SRC ... get last_viewed document
    if (url.searchParams.has("frame")) {
      response.end(
        `<html>
        <script>
        document.addEventListener("DOMContentLoaded", function() {
           const lastFile = localStorage.getItem("localstorage_lastfile");
           const pdfFrame = document.querySelector('frame[name="pdf"]');
           if (pdfFrame && !pdfFrame.src && lastFile) {
               pdfFrame.src = lastFile; // Charger l'URL sauvegardée
           }
          // alert(lastFile)
        });
        </script>
          <frameset cols=*,200>
            <frame name=pdf> 
            <frame src="${url.pathname}?side">
          </frameset>
        </html>`,
        "utf8"
      );
      return;
    }

    let files;
    try {
      files = await fsPromises.readdir(localUrl);
    } catch {
      response.end();
      return;
    }

    response.write(
      `<html>
         <head>
           <meta charset="utf-8">
           <style>
           body {
              margin: 10px 0;
            }
              h1, ol {
              padding-left: 13px !important;
            }
              ol {
                margin-top: 10px;
                border-top: 1px solid;
                padding-top: 5px !important;

              }
              html h1 {
                font-family: sans-serif;
              }
           a {  word-wrap: anywhere;  }
           h1 a,
           .folder a {color: #000}
           .file a {
              font-size: 14px;
              line-height: 18px;
              margin-top: 10px;
              display: block;
              margin-bottom: 17px !important;
                text-decoration: none;
            }
            .folder {
              font-size: 13px;
              font-family: sans-serif;
              font-weight: bold;
              line-height: 1.2em;
                margin-bottom: 12px;
                margin-top: 12px;

            }
            .folder a {
               text-decoration: navajowhite;
            }
               #return {
              margin-bottom: -13px;
              display: block;
            }
              #return, h1 a {
                text-decoration: none;
              }

              hr + #footer {
                font-size: 12px;
              }

              #footer p {
                margin: 0;
                padding-right: 5px;
                text-align: right;
                font-family: sans-serif;
              }
                #footer a {
                  color: #000;
                }
            a span {
              position: absolute;
              margin-left: -20px;
            }
            h1 a {
              padding-left: 16px;
            }
              h1 a.notlast {
                padding-left: 5px;
                  opacity: 0.6;
              }
              h1 a.notlast span {
              position: absolute;
              margin-left: -10px;
            }
              ol a:visited {
                color: #107102;
              }
                ol .folder a:visited {
                color: #000;
              }
                ol .a_file.active {
                  color: fuchsia;
                }
                  
                .a_folder.active {
                  color: #5c00ff !important;
                }
                .a_folder(:focus,:active)  {
                  color: blue !important;
                }
            #filename {
              position: fixed;
              bottom: 0;
              font-size: 10px;
              font-family: sans-serif;
              padding-left: 6px;
              padding-bottom: 6px;
            }
           </style>
         </head>
          <script>
            // Sauvegarde de l'URL actuelle de la page
             var currentURL = window.location.href;
             localStorage.setItem("currentURL", currentURL); // Sauvegarder dans newURL
             
             var pastURL = localStorage.getItem("pastURL");
              if (pastURL == null) { // Ajout de cette condition
                 
                  window.location.href = "http://localhost:8888/test/pdfs/?side";
                  localStorage.setItem("pastURL", "http://localhost:8888/test/pdfs/?side"); // Mettre à jour l'URL précédente 

             } else if (currentURL == "http://localhost:8888/test/pdfs/?side") {

                  if (currentURL != pastURL) {
                    window.location.href = pastURL;
                  }
             } else {
                  // alert(currentURL +" - VS - "+ pastURL)
                  localStorage.setItem("pastURL", currentURL); // Mettre à jour l'URL précédente 
             }
              
              document.addEventListener("DOMContentLoaded", function() {
                                  
                  var currentname = localStorage.getItem("localstorage_lastfile");
                  var decodedURL = decodeURIComponent(currentname);
                  // alert(decodedURL)

                  var fileName = decodedURL.substring(decodedURL.lastIndexOf('/') + 1);
                  document.getElementById('filename').textContent = fileName;


                  document.querySelectorAll('.a_file').forEach(fileLink => {
                      fileLink.addEventListener('click', function(event) {
                          
                          if (this.href != undefined) {
                            localStorage.setItem("localstorage_lastfile", this.href); // Sauvegarder l'URL du fichier
                          // } else {
                            // localStorage.setItem("localstorage_lastfile", ""); // REMOVE
                          }
                          let thisis= this;
                          this.classList.add("active");
                          document.querySelectorAll('.a_file').forEach(relinks => {
                            if (relinks !== thisis) {
                              relinks.classList.remove("active");
                            }
                          });


                          var currentname = localStorage.getItem("localstorage_lastfile");
                          var decodedURL = decodeURIComponent(currentname);
                          var fileName = decodedURL.substring(decodedURL.lastIndexOf('/') + 1);
                          document.getElementById('filename').textContent = fileName;

                      });

                      

                      if (fileLink.href === currentname) {
                          fileLink.classList.add("active");
                      }

                  });



                  var currentname_fldr = localStorage.getItem("localstorage_last_folder");
                  if (currentname_fldr) { // Vérifiez si la valeur existe
                      var decodedURL_fldr = decodeURIComponent(currentname_fldr);
                      // alert(decodedURL_fldr); // Affichez la valeur décodée
                  } else {
                      // alert("Aucune valeur trouvée pour 'localstorage_last_folder'"); // Message alternatif
                  }

                  document.querySelectorAll('.a_folder').forEach(folderLink => {
                    folderLink.addEventListener('click', function(event) {
                        
                        // alert("clic "+this.href)
                        if (this.href != undefined) {
                          localStorage.setItem("localstorage_last_folder", this.href); // Sauvegarder l'URL du fichier
                        }
                        let thisis= this;
                        this.classList.add("active");
                        document.querySelectorAll('.a_folder').forEach(refolders => {
                          if (refolders !== thisis) {
                            refolders.classList.remove("active");
                          }
                        });

                    });

                    if (folderLink.href === currentname_fldr) {
                        folderLink.classList.add("active");
                    } 
                    // alert(currentname_fldr)

                });
              });
           </script>
         <body>` // Début de la liste ordonnée
    );

    const segments = url.pathname.split('/').filter(Boolean); // Séparer les segments
    let currentPath = ""; // Chemin courant pour les liens

    const all = url.searchParams.has("all");
    const escapeHTML = untrusted =>
      // Escape untrusted input so that it can safely be used in a HTML response
      // in HTML and in HTML attributes.
      untrusted
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");


    response.write('<h1 style="font-size:14px;">');
        segments.forEach((segment, index) => {
          currentPath += `/${segment}`; // Construire le chemin courant
          // if (index < segments.length - 1) {
          if (  ( escapeHTML(segment) == "test" ) || ( escapeHTML(segment) == "pdfs") ) {

          }
          else if (index === segments.length - 1) {
            // const previousSegment = segments[index - 1] ? escapeHTML(segments[index - 1]) : '';
            response.write(`<div class="lastlast"><strong><a style="" href=".."><span id="last">>> </span>${escapeHTML(segment)}</a></strong></div>`); // Lien cliquable en gras
            // response.write(`<div><strong><a style="" href="${escapeHTML(currentPath)}"><span id="last">>> </span>${escapeHTML(segment)}</a></strong></div>`); // Lien cliquable en gras
          } else {
            response.write(`<div><a class="notlast" href="${escapeHTML(currentPath)}"><span>> </span>${escapeHTML(segment)}</a></div>`); // Lien cliquable
          }
        });
    response.write('</h1>'); // Fermer la balise h1

    response.write('<ol style="padding: 0;list-style: none;">'); // Début de la liste ordonnée

    // if (url.pathname !== "/") {
    //   response.write('<a id="return" href=".."><-</a><br>');
    // }


    // Trier les fichiers par date de modification (ordre décroissant)
    const fileStats = files.map(file => ({
      file,
      stat: fs.statSync(new URL(file, localUrl)),
    })).sort((a, b) => b.stat.mtime - a.stat.mtime); // Inverser l'ordre ici

    // console.log(JSON.stringify(fileStats, null, 2)); // Afficher les statistiques des fichiers en format JSON



    for (const { file } of fileStats) {
      let stat;
      const item = url.pathname + file;
      let href = "";
      let label = "";
      let extraAttributes = "";

      try {
        stat = fs.statSync(new URL(file, localUrl));
      } catch (ex) {
        href = encodeURI(item);
        label = `${file} (${ex})`;
        extraAttributes = ' style="color:red"';
      }

      if (stat) {
        if (stat.isDirectory()) {
          href = encodeURI(item);
          label = file;
          response.write(
            `<li class='folder'><a class='a_folder' href="${escapeHTML(href)}">${escapeHTML(label)}</a></li>` // Changement ici
          ); // Écrire le lien du dossier immédiatement
        } else if (path.extname(file).toLowerCase() === ".pdf") {
          href = `/web/viewer.html?file=${encodeURIComponent(item)}`;
          label = file;
          extraAttributes = ' target="pdf"';

          if (label) {
            response.write(
              `<li class='file'><a class='a_file' href="${escapeHTML(href)}"${extraAttributes}>${escapeHTML(label)}</a></li>` // Changement ici
            );
          }

        } else if (all) {
          href = encodeURI(item);
          label = file;
        }
      }

    }
    response.write(`</ol>`); // Fin de la liste ordonnée

    if (files.length === 0) {
      response.write("<p>No files found</p>");
    }

    if (!all && !url.searchParams.has("side")) {
      response.write(
        '<hr><div id="footer"><p>( Triés par date )</p><p>( <a href="?all">voir les non-pdf</a> )</p></div>'
      );
    }

    response.end("<div id='filename'></div></body></html>");
  }

  #serveFile(response, fileURL, fileSize) {
    const stream = fs.createReadStream(fileURL, { flags: "rs" });
    stream.on("error", error => {
      response.writeHead(500);
      response.end();
    });

    if (!this.disableRangeRequests) {
      response.setHeader("Accept-Ranges", "bytes");
    }
    response.setHeader("Content-Type", this.#getContentType(fileURL));
    response.setHeader("Content-Length", fileSize);
    if (this.cacheExpirationTime > 0) {
      const expireTime = new Date();
      expireTime.setSeconds(expireTime.getSeconds() + this.cacheExpirationTime);
      response.setHeader("Expires", expireTime.toUTCString());
    }
    response.writeHead(200);
    stream.pipe(response);
  }

  #serveFileRange(response, fileURL, fileSize, start, end) {
    const stream = fs.createReadStream(fileURL, {
      flags: "rs",
      start,
      end: end - 1,
    });
    stream.on("error", error => {
      response.writeHead(500);
      response.end();
    });

    response.setHeader("Accept-Ranges", "bytes");
    response.setHeader("Content-Type", this.#getContentType(fileURL));
    response.setHeader("Content-Length", end - start);
    response.setHeader(
      "Content-Range",
      `bytes ${start}-${end - 1}/${fileSize}`
    );
    response.writeHead(206);
    stream.pipe(response);
  }

  #getContentType(fileURL) {
    const extension = path.extname(fileURL.pathname).toLowerCase();
    return MIME_TYPES[extension] || DEFAULT_MIME_TYPE;
  }
}

// This supports the "Cross-origin" test in test/unit/api_spec.js
// It is here instead of test.js so that when the test will still complete as
// expected if the user does "gulp server" and then visits
// http://localhost:8888/test/unit/unit_test.html?spec=Cross-origin
function crossOriginHandler(url, request, response) {
  if (url.pathname === "/test/pdfs/basicapi.pdf") {
    if (url.searchParams.get("cors") === "withCredentials") {
      response.setHeader("Access-Control-Allow-Origin", request.headers.origin);
      response.setHeader("Access-Control-Allow-Credentials", "true");
    } else if (url.searchParams.get("cors") === "withoutCredentials") {
      response.setHeader("Access-Control-Allow-Origin", request.headers.origin);
    }
  }
}

export { WebServer };