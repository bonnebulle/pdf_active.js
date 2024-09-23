
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


            // Ajoutez cette fonction dans le script
            function openFrames(parentUrl, pdfUrl) {
              const pdfFrame = document.querySelector('frame[name="pdf"]');
              const listFrame = document.querySelector('frame[name="liste"]');
              
              if (pdfFrame) {
                pdfFrame.src = pdfUrl; // Ouvrir currentname dans la frame "pdf"
              }
              if (listFrame) {
                listFrame.src = parentUrl; // Ouvrir currentname_parent dans la frame "liste"
              }
            }
            
             
             document.addEventListener("DOMContentLoaded", function() {

                                 
                 var currentname = localStorage.getItem("localstorage_lastfile");
                 var decodedURL = decodeURIComponent(currentname);
                 // alert(decodedURL)

                 var fileName = decodedURL.substring(decodedURL.lastIndexOf('/') + 1);
                 var currentname_parent = decodedURL.substring(0, decodedURL.lastIndexOf('/')).replace("/web/viewer.html?file=",""); // Chemin vers le fichier
                 var patent_currentfile = <a href="#" onclick="openFrames('${currentname_parent}', '${currentname}'); return false;">${fileName}</a>;
                 document.getElementById('filename').innerHTML = patent_currentfile; // Remplacer le contenu
                 // alert(currentname_parent)


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
                         var currentname_parent = decodedURL.substring(0, decodedURL.lastIndexOf('/')).replace("/web/viewer.html?file=",""); // Chemin vers le fichier
                         var patent_currentfile = <a href="#" onclick="openFrames(currentname_parent, currentname); return false;">${fileName}</a>;
                           document.getElementById('filename').innerHTML = patent_currentfile; // Remplacer le contenu


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