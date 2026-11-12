# HYPEVERSE

Sitio web estático de reseñas y comunidad de videojuegos, películas y series. Incluye `index.html`, sus recursos de música y la configuración opcional de Supabase.

## Probar el sitio

Abre `index.html` en un navegador. Para publicarlo, sube **el contenido completo de esta carpeta** a la raíz de un repositorio de GitHub.

## Publicar con GitHub Pages

1. Crea un repositorio en GitHub.
2. Sube todos los archivos y la carpeta `assets` a la raíz del repositorio.
3. En el repositorio, abre **Settings → Pages**.
4. En **Build and deployment**, elige **Deploy from a branch**, selecciona `main` y `/(root)`, y guarda.
5. Cuando termine la publicación, abre el enlace que aparecerá en esa página.

## Datos y configuración

Sin credenciales de Supabase, el sitio funciona en modo local: la actividad se guarda en el navegador actual y no se sincroniza entre dispositivos. Para conectar un proyecto propio, configura `config.js` con la URL y la clave pública `anon` de Supabase y aplica `supabase-schema.sql` en ese proyecto. No publiques claves secretas de Supabase.
