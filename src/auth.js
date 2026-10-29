/**
 * Módulo de Autenticación para el Generador de Plan de Gestión de Software (SMP)
 * Universidad Centroamericana José Simeón Cañas (UCA) · Vicerrectoría de Investigación e Innovación
 * 
 * Proveedores soportados:
 * - Microsoft: OAuthProvider("microsoft.com")
 * - GitHub: GithubAuthProvider
 * - ORCID: OAuthProvider("oidc.orcid") [Requiere Google Cloud Identity Platform habilitado en Firebase]
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.13.0/firebase-app.js";
import {
  getAuth,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  GithubAuthProvider,
  OAuthProvider,
  setPersistence,
  browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/10.13.0/firebase-auth.js";

/* -------------------------------------------------------------------------- */
/*  CONFIGURACIÓN DE FIREBASE (Valores públicos de la consola de Firebase)   */
/* -------------------------------------------------------------------------- */
const firebaseConfig = {
  apiKey: "AIzaSyA-YZ0OYZjvFODUz0UekbA9w7BVYPulHzQ",
  authDomain: "midyear-calculus-64mm2.firebaseapp.com",
  projectId: "midyear-calculus-64mm2",
  appId: "1:609527045782:web:229aed3944470d16dbecb7"
};

// Variable de estado interna
let app = null;
let auth = null;
let currentUser = null;
const authListeners = [];

// Indicador de si la configuración contiene los marcadores de posición sin reemplazar
function isConfigured() {
  return (
    firebaseConfig.apiKey &&
    firebaseConfig.apiKey !== "[PEGAR]" &&
    firebaseConfig.authDomain &&
    firebaseConfig.authDomain !== "[PEGAR]" &&
    firebaseConfig.projectId &&
    firebaseConfig.projectId !== "[PEGAR]"
  );
}

// Inicialización de la app y autenticación con persistencia local
if (isConfigured()) {
  try {
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    setPersistence(auth, browserLocalPersistence).catch((err) => {
      console.warn("No se pudo establecer persistencia local:", err);
    });

    onAuthStateChanged(auth, (user) => {
      currentUser = user;
      notifyListeners(user);
    });
  } catch (err) {
    console.error("Error al inicializar Firebase Auth:", err);
  }
} else {
  console.info(
    "Firebase Auth: Configuración pendiente. Reemplace los marcadores [PEGAR] en auth.js con sus credenciales de Firebase."
  );
}

/* -------------------------------------------------------------------------- */
/*  PROVEEDORES DE AUTENTICACIÓN (OAuth 2.0 / OIDC)                           */
/* -------------------------------------------------------------------------- */

// 1. Microsoft (Cuentas institucionales / personales de Microsoft)
const microsoftProvider = new OAuthProvider("microsoft.com");
microsoftProvider.setCustomParameters({
  prompt: "select_account"
});

// 2. GitHub (Desarrolladores y repositorios de código abierto)
const githubProvider = new GithubAuthProvider();
githubProvider.addScope("read:user");

// 3. ORCID (Identificador persistente de investigadores/as - OIDC personalizado)
// NOTA ARQUITECTÓNICA: En Firebase, los proveedores personalizados "oidc.*" requieren
// tener habilitado Google Cloud Identity Platform (GCIP) en el proyecto.
const orcidProvider = new OAuthProvider("oidc.orcid");
orcidProvider.addScope("openid");
orcidProvider.addScope("/authenticate");
orcidProvider.addScope("/read-limited");

/* -------------------------------------------------------------------------- */
/*  MANEJO DE ERRORES EN ESPAÑOL                                              */
/* -------------------------------------------------------------------------- */
function getSpanishErrorMessage(error) {
  if (!error) return "Ocurrió un error inesperado durante la autenticación.";
  const code = error.code || "";

  switch (code) {
    case "auth/popup-blocked":
      return "La ventana emergente de inicio de sesión fue bloqueada por el navegador. Por favor habilite las ventanas emergentes (popups) para este sitio.";
    case "auth/popup-closed-by-user":
      return "El inicio de sesión se canceló porque la ventana emergente fue cerrada antes de completar el proceso.";
    case "auth/cancelled-popup-request":
      return "Se canceló la solicitud de autenticación anterior para dar paso a una nueva ventana.";
    case "auth/account-exists-with-different-credential":
      return "Ya existe una cuenta registrada con la misma dirección de correo electrónico mediante otro proveedor. Por favor inicie sesión con su proveedor original.";
    case "auth/network-request-failed":
      return "Error de red o conexión no disponible. Por favor verifique su conexión a Internet e intente nuevamente.";
    case "auth/operation-not-allowed":
      return "Este proveedor de autenticación no está activado en la consola de Firebase.";
    case "auth/configuration-not-found":
      return "Proveedor OIDC no encontrado. Para utilizar ORCID (oidc.orcid) es necesario activar Google Cloud Identity Platform en la consola de Firebase.";
    case "auth/invalid-api-key":
    case "auth/api-key-not-valid":
      return "La clave de API (apiKey) de Firebase no es válida. Verifique la configuración en auth.js.";
    case "auth/user-disabled":
      return "La cuenta de usuario ha sido inhabilitada por un administrador.";
    default:
      if (error.message && error.message.includes("NO_CONFIG")) {
        return "Firebase no ha sido configurado. Por favor reemplace los marcadores [PEGAR] en auth.js con las credenciales de su proyecto.";
      }
      return error.message || "No fue posible completar la autenticación. Por favor intente de nuevo.";
  }
}

/* -------------------------------------------------------------------------- */
/*  EXTRACCIÓN DE ORCID iD                                                   */
/* -------------------------------------------------------------------------- */
/**
 * Extrae y formatea el ORCID iD (0000-000X-XXXX-XXXX) del usuario autenticado.
 * ORCID vía OIDC devuelve el iD en el campo sub/uid o en los datos de proveedor.
 */
function extractOrcidId(user) {
  if (!user) return "";

  // Expresión regular para coincidir con un ORCID iD estándar (16 dígitos en grupos de 4)
  const orcidRegex = /(\d{4}-\d{4}-\d{4}-\d{3}[\dX])/i;

  // 1. Revisar uid del usuario (en OIDC suele ser directamente el ORCID iD)
  if (user.uid) {
    const match = user.uid.match(orcidRegex);
    if (match) return match[1].toUpperCase();
  }

  // 2. Revisar reloadUserInfo o screenName si viniera mapeado
  if (user.reloadUserInfo && user.reloadUserInfo.screenName) {
    const match = user.reloadUserInfo.screenName.match(orcidRegex);
    if (match) return match[1].toUpperCase();
  }

  // 3. Revisar providerData
  if (Array.isArray(user.providerData)) {
    for (const p of user.providerData) {
      if (p.uid) {
        const match = p.uid.match(orcidRegex);
        if (match) return match[1].toUpperCase();
      }
    }
  }

  // 4. Si el uid es puramente el iD sin guiones (16 caracteres), formatearlo
  if (user.uid && /^\d{15}[\dX]$/i.test(user.uid)) {
    return user.uid.replace(/(.{4})(.{4})(.{4})(.{4})/g, "$1-$2-$3-$4").toUpperCase();
  }

  return "";
}

/* -------------------------------------------------------------------------- */
/*  MÉTODOS PÚBLICOS DE AUTENTICACIÓN                                         */
/* -------------------------------------------------------------------------- */

async function ensureAuth() {
  if (!isConfigured() || !auth) {
    const err = new Error(
      "Firebase no ha sido configurado aún. Pegue las credenciales de su proyecto en auth.js reemplazando los marcadores [PEGAR]."
    );
    err.code = "NO_CONFIG";
    throw err;
  }
  return auth;
}

/**
 * Iniciar sesión con Microsoft
 */
export async function loginWithMicrosoft() {
  const currentAuth = await ensureAuth();
  try {
    const result = await signInWithPopup(currentAuth, microsoftProvider);
    return {
      success: true,
      user: result.user,
      provider: "microsoft.com"
    };
  } catch (error) {
    console.error("Error en loginWithMicrosoft:", error);
    return {
      success: false,
      error: error,
      errorMessage: getSpanishErrorMessage(error)
    };
  }
}

/**
 * Iniciar sesión con GitHub
 */
export async function loginWithGithub() {
  const currentAuth = await ensureAuth();
  try {
    const result = await signInWithPopup(currentAuth, githubProvider);
    return {
      success: true,
      user: result.user,
      provider: "github.com"
    };
  } catch (error) {
    console.error("Error en loginWithGithub:", error);
    return {
      success: false,
      error: error,
      errorMessage: getSpanishErrorMessage(error)
    };
  }
}

/**
 * Iniciar sesión con ORCID
 */
export async function loginWithOrcid() {
  const currentAuth = await ensureAuth();
  try {
    const result = await signInWithPopup(currentAuth, orcidProvider);
    const orcidId = extractOrcidId(result.user);
    return {
      success: true,
      user: result.user,
      orcidId: orcidId,
      provider: "oidc.orcid"
    };
  } catch (error) {
    console.error("Error en loginWithOrcid:", error);
    return {
      success: false,
      error: error,
      errorMessage: getSpanishErrorMessage(error)
    };
  }
}

/**
 * Cerrar sesión activa
 */
export async function logout() {
  if (!auth) {
    currentUser = null;
    notifyListeners(null);
    return { success: true };
  }
  try {
    await signOut(auth);
    currentUser = null;
    notifyListeners(null);
    return { success: true };
  } catch (error) {
    console.error("Error en logout:", error);
    return {
      success: false,
      error: error,
      errorMessage: getSpanishErrorMessage(error)
    };
  }
}

/**
 * Obtener usuario actualmente autenticado
 */
export function getCurrentUser() {
  return currentUser;
}

/**
 * Verificar si hay sesión activa persistida
 */
export function isLoggedIn() {
  return currentUser !== null;
}

/**
 * Suscribirse a cambios en el estado de autenticación
 */
export function onAuthStateChange(callback) {
  if (typeof callback === "function") {
    authListeners.push(callback);
    // Notificar inmediatamente el estado actual
    callback(currentUser);
  }
  return () => {
    const idx = authListeners.indexOf(callback);
    if (idx !== -1) authListeners.splice(idx, 1);
  };
}

function notifyListeners(user) {
  authListeners.forEach((fn) => {
    try {
      fn(user);
    } catch (e) {
      console.error("Error en callback de authStateChange:", e);
    }
  });
}

/* -------------------------------------------------------------------------- */
/*  EXPOSICIÓN GLOBAL EN WINDOW (Para interoperabilidad sin bundlers)        */
/* -------------------------------------------------------------------------- */
const SMPAuth = {
  isConfigured,
  loginWithMicrosoft,
  loginWithGithub,
  loginWithOrcid,
  logout,
  getCurrentUser,
  isLoggedIn,
  onAuthStateChange,
  extractOrcidId,
  getSpanishErrorMessage
};

if (typeof window !== "undefined") {
  window.SMPAuth = SMPAuth;
}

export default SMPAuth;
