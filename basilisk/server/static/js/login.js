/**
 * Basilisk Login Interface
 * Handles authentication, rate limiting, and animated background.
 */

const LOGIN_ENDPOINT = "/api/v1/auth/login";

if (window.location.hostname === '127.0.0.1') {
    window.location.href = window.location.href.replace('127.0.0.1', 'localhost');
}

async function doLogin() {
    const u = document.getElementById('username').value;
    const p = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    const status = document.getElementById('status-text');

    if (!u || !p) {
        shakeForm();
        typeText(status, "⚠️ ERROR: MISSING CREDENTIALS", true);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> AUTHENTICATING...';
    typeText(status, "⚡ ESTABLISHING SECURE HANDSHAKE...", false);

    try {
        const res = await fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: u, password: p})
        });

        if (res.status === 200) {
            typeText(status, "✅ ACCESS GRANTED. REDIRECTING...", false);
            const data = await res.json();
            setTimeout(() => window.location.href = data.redirect || '/', 800);
        } else {
            shakeForm();
            btn.disabled = false;
            btn.innerHTML = '<span>RETRY UPLINK</span><i class="fa-solid fa-rotate-right"></i>';
            typeText(status, "❌ ACCESS DENIED: INVALID KEY", true);
        }
    } catch(e) {
        btn.disabled = false;
        btn.innerHTML = 'RETRY CONNECTION';
        typeText(status, "⛔ FATAL: SERVER UNREACHABLE", true);
    }
}

function typeText(element, text, isError) {
    element.className = isError ? 'status-line text-danger' : 'status-line';
    element.innerText = text;
}

function shakeForm() {
    const form = document.querySelector('.login-container');
    form.animate([
        { transform: 'translateX(0)' },
        { transform: 'translateX(-10px)' },
        { transform: 'translateX(10px)' },
        { transform: 'translateX(0)' }
    ], { duration: 300 });
}

document.getElementById('password').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') doLogin();
});

const canvas = document.getElementById('networkCanvas');
const ctx = canvas.getContext('2d');
let particles = [];

function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}
window.addEventListener('resize', resize);
resize();

class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.vx = (Math.random() - 0.5) * 0.5;
        this.vy = (Math.random() - 0.5) * 0.5;
        this.size = Math.random() * 2;
    }
    
    update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
        if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }
    
    draw() {
        ctx.fillStyle = 'rgba(16, 185, 129, 0.5)'; 
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
    }
}

function initParticles() {
    particles = [];
    const count = Math.min(window.innerWidth / 10, 100); 
    for (let i = 0; i < count; i++) {
        particles.push(new Particle());
    }
}

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    for (let i = 0; i < particles.length; i++) {
        for (let j = i; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            if (distance < 150) {
                ctx.beginPath();
                ctx.strokeStyle = `rgba(16, 185, 129, ${1 - distance / 150})`;
                ctx.lineWidth = 0.5;
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.stroke();
            }
        }
    }

    particles.forEach(p => {
        p.update();
        p.draw();
    });
    
    requestAnimationFrame(animate);
}

initParticles();
animate();