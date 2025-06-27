// Theme Switcher Functionality
class ThemeSwitcher {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'default';
        this.init();
    }

    init() {
        console.log('Theme switcher init, current theme:', this.currentTheme);
        this.applyTheme(this.currentTheme);
        this.createSwitcher();
        this.addLcarsEffects();
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        localStorage.setItem('theme', theme);
        
        // Toggle theme-specific elements
        document.querySelectorAll('[data-theme-target]').forEach(el => {
            const target = el.getAttribute('data-theme-target');
            if (target === theme) {
                el.classList.remove('hidden');
                if (el.tagName.toLowerCase() === 'div') {
                    el.classList.add('block');
                } else {
                    el.classList.add('inline');
                }
            } else {
                el.classList.add('hidden');
                el.classList.remove('block', 'inline');
            }
        });

        // Add LCARS-specific classes when in LCARS mode
        if (theme === 'lcars') {
            this.enableLcarsMode();
        } else {
            this.disableLcarsMode();
        }
        
        // Force layout recalculation
        document.body.offsetHeight;
    }

    enableLcarsMode() {
        // Add LCARS classes to existing elements
        document.querySelectorAll('.bg-white').forEach(el => {
            if (!el.classList.contains('lcars-card')) {
                el.classList.add('lcars-card');
            }
        });

        document.querySelectorAll('table').forEach(el => {
            if (!el.classList.contains('lcars-table')) {
                el.classList.add('lcars-table');
            }
        });

        document.querySelectorAll('button:not(.theme-toggle)').forEach(el => {
            if (!el.classList.contains('lcars-button')) {
                el.classList.add('lcars-button');
            }
        });

        document.querySelectorAll('input, select, textarea').forEach(el => {
            if (!el.classList.contains('lcars-input')) {
                el.classList.add('lcars-input');
            }
        });

        // Fix grid layouts
        document.querySelectorAll('.grid').forEach(el => {
            if (!el.classList.contains('lcars-grid')) {
                el.classList.add('lcars-grid');
            }
        });

        // Add sound effects and animations
        this.addLcarsBeeps();
    }

    disableLcarsMode() {
        // Remove LCARS classes
        document.querySelectorAll('.lcars-card, .lcars-table, .lcars-button, .lcars-input, .lcars-grid').forEach(el => {
            el.classList.remove('lcars-card', 'lcars-table', 'lcars-button', 'lcars-input', 'lcars-grid');
        });
    }

    addLcarsEffects() {
        // Add hover sound effects for LCARS mode
        document.addEventListener('mouseover', (e) => {
            if (this.currentTheme === 'lcars' && (e.target.matches('button') || e.target.matches('.lcars-panel'))) {
                this.playLcarsBeep();
            }
        });

        // Add startup sound when switching to LCARS
        document.addEventListener('click', (e) => {
            if (this.currentTheme === 'lcars' && e.target.matches('button')) {
                this.playLcarsClick();
            }
        });
    }

    addLcarsBeeps() {
        // Create audio context for LCARS sounds (optional - can be commented out if no audio needed)
        try {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }
        } catch (e) {
            console.log('Audio context not available');
        }
    }

    playLcarsBeep() {
        // Optional: Add LCARS-style beep sound
        // This would require audio files or web audio API implementation
    }

    playLcarsClick() {
        // Optional: Add LCARS-style click sound
        // This would require audio files or web audio API implementation
    }

    createSwitcher() {
        const button = document.getElementById('themeToggle');
        if (!button) return;
        
        button.textContent = this.currentTheme === 'lcars' ? 'STANDARD MODE' : 'LCARS MODE';
        
        // Add LCARS-specific styling to the button
        if (this.currentTheme === 'lcars') {
            button.classList.add('lcars-button');
        }
        
        button.addEventListener('click', () => {
            const newTheme = this.currentTheme === 'default' ? 'lcars' : 'default';
            this.applyTheme(newTheme);
            button.textContent = newTheme === 'lcars' ? 'STANDARD MODE' : 'LCARS MODE';
            
            // Update button styling
            if (newTheme === 'lcars') {
                button.classList.add('lcars-button');
                this.showLcarsStartup();
            } else {
                button.classList.remove('lcars-button');
            }
        });
    }

    showLcarsStartup() {
        // Show LCARS startup animation
        const startup = document.createElement('div');
        startup.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #000;
            color: #FF9900;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            font-family: 'Courier New', monospace;
            font-size: 24px;
            text-transform: uppercase;
            letter-spacing: 3px;
        `;
        startup.innerHTML = `
            <div style="text-align: center;">
                <div style="margin-bottom: 20px;">LCARS INTERFACE INITIALIZING...</div>
                <div style="font-size: 14px; color: #9999FF;">STARFLEET COMMAND AUTHORIZED</div>
            </div>
        `;
        
        document.body.appendChild(startup);
        
        setTimeout(() => {
            startup.style.opacity = '0';
            startup.style.transition = 'opacity 0.5s';
            setTimeout(() => {
                document.body.removeChild(startup);
            }, 500);
        }, 1500);
    }
}

// Initialize theme switcher when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing theme switcher...');
    new ThemeSwitcher();
});