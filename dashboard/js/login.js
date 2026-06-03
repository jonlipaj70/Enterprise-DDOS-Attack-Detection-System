document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('login-form');
    const error = document.getElementById('login-error');
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        error.classList.add('hidden');
        const payload = {
            username: form.username.value,
            password: form.password.value,
        };
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!response.ok) {
                error.textContent = 'Invalid username or password.';
                error.classList.remove('hidden');
                return;
            }
            window.location.assign('/');
        } catch (_error) {
            error.textContent = 'The sensor API is unavailable.';
            error.classList.remove('hidden');
        }
    });
});
