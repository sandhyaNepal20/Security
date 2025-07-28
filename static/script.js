document.addEventListener('DOMContentLoaded', () => {
    const ratings = document.querySelectorAll('.rating');

    ratings.forEach(rating => {
        const stars = rating.querySelectorAll('.star');

        stars.forEach(star => {
            star.addEventListener('click', () => {
                const value = parseInt(star.dataset.value);
                const currentSelected = parseInt(rating.dataset.selected);

                if (value === currentSelected) {
                    rating.dataset.selected = 0;
                    stars.forEach(s => s.classList.remove('active'));
                } else {
                    rating.dataset.selected = value;
                    stars.forEach(s => {
                        s.classList.toggle('active', parseInt(s.dataset.value) <= value);
                    });
                }
            });
        });
    });
});


document.addEventListener('DOMContentLoaded', () => {
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });
});

function smoothScroll(target, duration) {
    const targetPosition = target.getBoundingClientRect().top + window.pageYOffset;
    const startPosition = window.pageYOffset;
    const distance = targetPosition - startPosition;
    let startTime = null;

    function animation(currentTime) {
        if (startTime === null) startTime = currentTime;
        const timeElapsed = currentTime - startTime;
        // easing function for smoothness (easeInOutCubic)
        const run = easeInOutCubic(timeElapsed, startPosition, distance, duration);
        window.scrollTo(0, run);
        if (timeElapsed < duration) {
            requestAnimationFrame(animation);
        }
    }

    // easeInOutCubic easing function
    function easeInOutCubic(t, b, c, d) {
        t /= d / 2;
        if (t < 1) return c / 2 * t * t * t + b;
        t -= 2;
        return c / 2 * (t * t * t + 2) + b;
    }

    requestAnimationFrame(animation);
}

// Attach smooth scroll event to nav links with class 'nav-link'
document.querySelectorAll('a.nav-link').forEach(link => {
    link.addEventListener('click', function (e) {
        e.preventDefault();
        const targetID = this.getAttribute('href').substring(1);
        const targetSection = document.getElementById(targetID);
        if (targetSection) {
            smoothScroll(targetSection, 700); // 600ms duration for smooth scroll
        }
    });
});

const categoryBtn = document.getElementById('categoryBtn');
const categoryMenu = document.getElementById('categoryMenu');

categoryBtn.addEventListener('click', () => {
    const isVisible = categoryMenu.style.display === 'block';
    categoryMenu.style.display = isVisible ? 'none' : 'block';
});

// Optional: close dropdown when clicking outside
document.addEventListener('click', (event) => {
    if (!categoryBtn.contains(event.target) && !categoryMenu.contains(event.target)) {
        categoryMenu.style.display = 'none';
    }
});


