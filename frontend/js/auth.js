"use strict";

document.addEventListener('DOMContentLoaded', initializeAuthPage);

function authMessage(message, kind = 'error') {
  const element = document.getElementById('auth-message');
  element.textContent = message;
  element.dataset.kind = kind;
  element.hidden = false;
}

function authRedirectTarget() {
  const candidate = new URLSearchParams(window.location.search).get('next') || '/index.html';
  if (!candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('\\')) return '/index.html';
  try {
    const url = new URL(candidate, window.location.origin);
    return url.origin === window.location.origin ? `${url.pathname}${url.search}${url.hash}` : '/index.html';
  } catch (_) {
    return '/index.html';
  }
}

async function initializeAuthPage() {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const switchBox = document.getElementById('auth-switch');
  const switchButton = document.getElementById('auth-switch-button');
  const switchCopy = document.getElementById('auth-switch-copy');
  const description = document.getElementById('auth-description');
  const title = document.getElementById('auth-title');

  try {
    const config = await API.auth.config();
    if (config.auth_mode === 'local_users') {
      try {
        await API.auth.me();
        window.location.replace(authRedirectTarget());
        return;
      } catch (_) {
        // No current session: keep the sign-in form available.
      }
      if (config.registration_enabled) {
        switchBox.hidden = false;
        switchButton.addEventListener('click', () => {
          const registering = registerForm.hidden;
          registerForm.hidden = !registering;
          loginForm.hidden = registering;
          title.textContent = registering ? 'Create account' : 'Sign in';
          description.textContent = registering
            ? 'Create an Analyst account for the configured local workspace.'
            : 'Use your local workspace account to continue.';
          switchCopy.textContent = registering ? 'Already registered?' : 'Need an account?';
          switchButton.textContent = registering ? 'Sign in' : 'Create account';
          document.getElementById(registering ? 'register-name' : 'login-email').focus();
        });
      } else {
        description.textContent = 'Use the local account created by your workspace administrator.';
      }
      loginForm.addEventListener('submit', submitLogin);
      registerForm.addEventListener('submit', submitRegistration);
      return;
    }

    loginForm.hidden = true;
    registerForm.hidden = true;
    switchBox.hidden = true;
    title.textContent = config.auth_mode === 'oidc_jwt' ? 'Organization sign-in' : 'Authentication unavailable';
    description.textContent = config.auth_mode === 'oidc_jwt'
      ? 'This deployment uses the organization identity provider. Open 5STONES through your organization’s approved sign-in flow.'
      : config.auth_mode === 'disabled'
        ? 'Authentication is disabled for this local development instance.'
        : 'The configured authentication mode is not supported by this sign-in page.';
  } catch (error) {
    loginForm.hidden = true;
    registerForm.hidden = true;
    authMessage(error.message || 'Could not load authentication configuration.');
  }
}

async function submitLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await API.auth.login({
      email: form.elements.email.value.trim(),
      password: form.elements.password.value,
    });
    window.location.replace(authRedirectTarget());
  } catch (error) {
    authMessage(error.message || 'Sign in failed.');
  } finally {
    button.disabled = false;
  }
}

async function submitRegistration(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const password = form.elements.password.value;
  if (password !== form.elements.confirm.value) {
    authMessage('Passwords do not match.');
    form.elements.confirm.focus();
    return;
  }
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await API.auth.register({
      email: form.elements.email.value.trim(),
      password,
      display_name: form.elements.name.value.trim(),
      registration_key: form.elements.registration_key.value,
    });
    window.location.replace(authRedirectTarget());
  } catch (error) {
    authMessage(error.message || 'Account registration failed.');
  } finally {
    button.disabled = false;
  }
}
