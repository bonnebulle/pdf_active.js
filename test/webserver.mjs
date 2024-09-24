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
    this.countOtherFiles = 0; // Déclaration de la variable count
    this.countNormalFiles = 0; // Compteur pour les fichiers normaux
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

  
  //! ---- FRAMEs
  async #serveDirectoryIndex(response, url, localUrl) {
    response.setHeader("Content-Type", "text/html");
    response.writeHead(200);
     
    // IF NO SRC ... get last_viewed document
    if (url.searchParams.has("frame")) {
      response.end(
        `<html>
        <script>
        //! ---- GLOBAL JS
        //! ---- LOAD LAST SAVED ----
        document.addEventListener("DOMContentLoaded", function() {
           const lastFile = localStorage.getItem("localstorage_lastfile");
           const pdfFrame = document.querySelector('frame[name="pdf"]');
           if (pdfFrame && !pdfFrame.src && lastFile) {
               pdfFrame.src = lastFile; // Charger l'URL sauvegardée
           }
        });
        </script>
          <frameset cols=*,200>
            <frame name=pdf> 
            <frame name="liste" src="${url.pathname}?side">
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
            <!-- CSS -->
            <link rel="stylesheet" href="/test/liste_viewer.css">
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
                          
              ///// AUtorun

                var currentname = localStorage.getItem("localstorage_lastfile");
                if (currentname) {
                    var decodedURL = decodeURIComponent(currentname);
                    // alert(decodedURL)

                    var fileName = decodedURL.substring(decodedURL.lastIndexOf('/') + 1);
                    var currentname_parent = decodedURL.substring(0, decodedURL.lastIndexOf('/')).replace("/web/viewer.html?file=",""); // Chemin vers le fichier
                    var patent_currentfile="<div><span>< </span><a id='backlink' data-url='"+currentname+"' href='"+currentname_parent+"?all' target='liste'>"+fileName+"</a></div>"
                    if ( document.getElementById('filename') ) {
                      document.getElementById('filename').innerHTML = patent_currentfile; // Remplacer le contenu
                    }
                }

                /////// ////// ////////  FILES

                document.querySelectorAll('.a_file').forEach(fileLink => {
                    fileLink.addEventListener('click', function(event) {
                        
                        if (this.href != undefined) {
                          event.preventDefault();

                          localStorage.setItem("localstorage_lastfile", this.href); // Sauvegarder l'URL du fichier

                          var currentname = this.href;
                          var decodedURL = decodeURIComponent(this.href);
                          var fileName = decodedURL.substring(decodedURL.lastIndexOf('/') + 1);
                          
                          var currentname_parent = decodedURL.substring(0, decodedURL.lastIndexOf('/')).replace("/web/viewer.html?file=",""); // Chemin vers le fichier
                          var patent_currentfile="<div><span>< </span><a id='backlink' data-url='"+currentname+"' href='"+currentname_parent+"?all' target='liste'>"+fileName+"</a></div>"
                          document.getElementById('filename').innerHTML = patent_currentfile; // Remplacer le contenu

                          const pdfFrame = window.parent.frames['pdf']; // Accès par nom
                          pdfFrame.location.href = currentname;

                        }

                        let thisis= this;
                        this.classList.add("active");
                        document.querySelectorAll('.a_file').forEach(relinks => {
                          if (relinks !== thisis) {
                            relinks.classList.remove("active");
                          }
                        });


                    });
                   

                    if (fileLink.href === currentname) {
                        fileLink.classList.add("active");
                    }

                }); // a_file

                ///// /////// ///////// FOLDERS

                var currentname_fldr = localStorage.getItem("localstorage_last_folder");
                if (currentname_fldr) { 
                    var decodedURL_fldr = decodeURIComponent(currentname_fldr);
                  
                } else {
                  
                  const currentname = window.parent.frames['pdf'].location.host; // Accès par nom
                  
                  // If NO HOST (pdf frame (empty))
                  if (!currentname || !currentname.host=="" || currentname.length < 10) { 
                    console.warn("empty_pdf") 
                    // window.parent.classList.add("empty"); // Ajout de la classe ici

                  } else {
                    var decodedURL = decodeURIComponent(currentname);
                    var currentname_parent = decodedURL.substring(0, decodedURL.lastIndexOf('/')).replace("/web/viewer.html?file=",""); // Chemin vers le fichier
                    localStorage.setItem("localstorage_last_folder", currentname_parent); // Sauvegarder l'URL du fichier
                    alert("currentname_parent = "+currentname_parent) 
                  } // If NO HOST (pdf frame (empty))

                } // if currentname_fldr

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

              }); // a_folder

              // LEGACY
              // document.querySelectorAll('#backlink').forEach(backlink => {
              //   backlink.addEventListener('click', function(event) {
              //     event.preventDefault();
              //     alert("clic")
              //   });
              // });

            }); // document.addEventListener("DOMContentLoaded", function() { (( Document ready... ))
           </script>
         <body>` // Début de la liste ordonnée
    );

    const segments = url.pathname.split('/').filter(Boolean); // Séparer les segments
    let currentPath = ""; // Chemin courant pour les liens

    const alll = url.searchParams.has("all");
    const pdfs = url.searchParams.has("pdfs") || !url.searchParams.has("pdfs");
    const escapeHTML = untrusted =>
      // Escape untrusted input so that it can safely be used in a HTML response
      // in HTML and in HTML attributes.
      untrusted
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");

    // -- FOLDERS PATH
    response.write('<h1 style="font-size:14px;">');
        segments.forEach((segment, index) => {
          currentPath += `/${segment}`; 
          // if (index < segments.length - 1) {
          if (  ( escapeHTML(segment) == "test" ) || ( escapeHTML(segment) == "pdfs") ) {

          }
          else if (index === segments.length - 1) {
            // const previousSegment = segments[index - 1] ? escapeHTML(segments[index - 1]) : '';
            response.write(`<div class="lastlast"><strong><a style="" href=".."><span id="last">> </span>${escapeHTML(segment)}</a></strong></div>`); // Lien cliquable en gras
            // response.write(`<div><strong><a style="" href="${escapeHTML(currentPath)}"><span id="last">>> </span>${escapeHTML(segment)}</a></strong></div>`); // Lien cliquable en gras
          } else {
            response.write(`<div><a class="notlast" href="${escapeHTML(currentPath)}"><span>> </span>${escapeHTML(segment)}</a></div>`); // Lien cliquable
          }
        });
    response.write('</h1>'); // Fermer la balise h1
    // if (url.pathname !== "/") {
    //   response.write('<a id="return" href=".."><-</a><br>');
    // }

    // -- FILE LISTING
    response.write('<ol style="padding: 0;list-style: none;">'); 
    // Trier les fichiers par type (dossiers d'abord, puis fichiers)
    const fileStats = files.map(file => ({
      file,
      stat: fs.statSync(new URL(file, localUrl)),
    })).sort((a, b) => {
      if (a.stat.isDirectory() && !b.stat.isDirectory()) return -1; // Dossier avant fichier
      if (!a.stat.isDirectory() && b.stat.isDirectory()) return 1;  // Fichier après dossier
      return b.stat.mtime - a.stat.mtime; // Trier par date de modification
    });

    // console.log(JSON.stringify(fileStats, null, 2)); 

    // TRUNCATE Long files names (du milieux)
    function truncateMiddle(text, maxLength) {
      if (text.length <= maxLength) return text;
      const halfLength = Math.floor(maxLength / 2);
      return `${text.slice(0, halfLength)}...${text.slice(-halfLength)}`;
    }

    let countNormalFiles = 0;
    let countOtherFiles = 0; // Non-pdf files

    const valides_extensions = [".html", ".css", ".text"]; // Déclaration de l'array des extensions valides


    for (const { file } of fileStats) {
      let stat;
      const item = url.pathname + file;
      let href = "";
      let label = "";
      let extraAttributes = "";
    
      try {
        stat = fs.statSync(new URL(file, localUrl));
        // console.log("oktry == " + file)
      } catch (ex) {
        href = encodeURI(item);
        label = `${file} (${ex})`;
        extraAttributes = ' style="color:red"';
        console.log("error catch files == " + file +"("+ex+")")
      }
      
      const file_extension = path.extname(file).toLowerCase(); // Obtenir l'extension du fichier
      // Compter les fichiers normaux avant la vérification de l'état
      if (file_extension === ".pdf") {
        countNormalFiles++; 
        console.log("f1 == "+ escapeHTML(file))
      } else if (valides_extensions.includes(file_extension)) { // Vérifie si l'extension est .pdf ou dans valides_extensions
        countOtherFiles++;
        console.log("f3 == "+ escapeHTML(file))
      } else if (stat.isDirectory()) {
        console.log("directory == \n"+ escapeHTML(file))
      } else {
        console.log("fx == "+ escapeHTML(file))
      }
      // console.log("countOtherFiles == "+countOtherFiles)
      // console.log("countNormalFiles == "+countNormalFiles)

    }
    

    for (const { file } of fileStats) {
      let stat;
      const item = url.pathname + file;
      let href = "";
      let label = "";
      let extraAttributes = "";


    
      try {
        stat = fs.statSync(new URL(file, localUrl));
        // console.log("oktry == " + file)
      } catch (ex) {
        href = encodeURI(item);
        label = `${file} (${ex})`;
        extraAttributes = ' style="color:red"';
        console.log("error catch files == " + file +"("+ex+")")
      }


      if (stat) {


        if (stat.isDirectory()) {
          href = encodeURI(item);
          label = file;
          // console.log("folder")
          response.write(
            `<li class='folder f1'><a class='a_folder' href="${escapeHTML(href)}">${escapeHTML(truncateMiddle(label, 40))}</a></li>` 
          ); // Écrire le lien du dossier immédiatement

        } else if (path.extname(file).toLowerCase() === ".pdf") {
          href = `/web/viewer.html?file=${encodeURIComponent(item)}`;
          label = file;
          extraAttributes = ' target="pdf"';

          if (label && !stat.isDirectory()) {
            response.write(
              `<li class='file f2'><a class='a_file' href="${escapeHTML(href)}"${extraAttributes}>${escapeHTML(truncateMiddle(label, 40))}</a></li>`
            );
            // this.countNormalFiles++; // Incrémenter le compteur pour les fichiers normaux
          }

        } else if ( (countNormalFiles == 0) || alll ) { // NON PDFs + const all = url.searchParams.has("all");
          href = encodeURI(item);
          // console.log("DEBUG f3-- = " +item)
          // console.log(this.countNormalFiles)
          // console.log(pdfs)

          label = file;
          response.write(
            `<li class='file f3'><a class='a_file' href="${escapeHTML(href)}"${extraAttributes}>${escapeHTML(truncateMiddle(label, 40))}</a></li>` 
          )
          
        // } else {
          // this.count++; // Incrémenter la variable de classe
        }
      }

    }
    response.write(`</ol>`); // Fin de la liste ordonnée

    if (files.length === 0) {
      response.write("<p>No files found</p>");
    }

    if ((countOtherFiles == 0)) {
      response.write(
        '<hr><div id="footer"><p>il n\'y a que des .pdf</p><p>( Triés par date )</p></div>'

      );
    }
    else if ((countNormalFiles == 0)) {
      response.write(
        '<hr><div id="footer"><p>! pas de .pdf</p><p>( Triés par date )</p></div>'

      );
    }
    else if ((countOtherFiles > 0) && !alll && (countNormalFiles != 0)) {
      response.write(
        '<hr><div id="footer"><p><a href="?all">voir les non-pdf</a> ( '+countOtherFiles+' )</p><p>( Triés par date )</p></div>'
      );
    } else if (!alll && !url.searchParams.has("side") && (countNormalFiles > 0)) {
      // if (countNormalFiles > 0) {
        console.log("pas de PDFs");
        response.write(
          '<hr><div id="footer" class="no_pdfs"><p><a href="?pdfs">voir les pdf seulement</a> ( '+countNormalFiles+' )</p><p>( Triés par date )</p></div>'
        );
      // }
    } else if (alll && !url.searchParams.has("side") && (countNormalFiles > 0)) {
      response.write(
        '<hr><div id="footer"><p>( filtrer : <a href="?pdfs">pdf seulement</a> )</p><p>( Triés par date )</p></div>'
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
      console.warn("errror");
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
    // console.warn(extension);
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