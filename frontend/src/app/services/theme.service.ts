import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

/**
 * Theme Service
 * 
 * Manages application theme switching between light and dark modes.
 * Provides reactive theme state management with localStorage persistence
 * and system preference detection.
 * 
 * Features:
 * - Light/Dark mode switching
 * - System preference detection
 * - LocalStorage persistence
 * - Reactive state management
 * - CSS class management for theme application
 * 
 * Usage:
 * - Inject service in components
 * - Subscribe to isDarkMode$ for reactive updates
 * - Call toggleDarkMode() to switch themes
 * - Theme preference is automatically saved and restored
 * 
 * CSS Classes:
 * - 'my-app-dark': Applied when dark mode is active
 * - 'surface-50': Applied when light mode is active
 * 
 * @example
 * // In component
 * constructor(private themeService: ThemeService) {
 *   this.themeService.isDarkMode$.subscribe(isDark => {
 *     // React to theme changes
 *   });
 * }
 * 
 * // Toggle theme
 * this.themeService.toggleDarkMode();
 * 
 * @example
 * // CSS usage
 * .my-app-dark {
 *   background-color: #1a1a1a;
 *   color: #ffffff;
 * }
 * 
 * .surface-50 {
 *   background-color: #fafafa;
 *   color: #000000;
 * }
 */
@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * BehaviorSubject for dark mode state
   * Provides reactive updates when theme changes
   */
  private isDarkMode = new BehaviorSubject<boolean>(false);

  /**
   * Observable for dark mode state
   * Subscribe to this for reactive theme updates
   */
  isDarkMode$ = this.isDarkMode.asObservable();

  // ============================================================================
  // CONSTRUCTOR
  // ============================================================================

  constructor() {
    this.initializeTheme();
  }

  // ============================================================================
  // PUBLIC METHODS
  // ============================================================================

  /**
   * Toggle between light and dark mode
   * 
   * Switches the current theme and persists the preference
   * to localStorage for future sessions.
   * 
   * @example
   * this.themeService.toggleDarkMode();
   */
  toggleDarkMode(): void {
    this.setDarkMode(!this.isDarkMode.value);
  }

  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================

  /**
   * Initialize theme based on saved preference or system preference
   * 
   * Checks localStorage for saved theme preference first,
   * then falls back to system preference if no saved preference exists.
   * 
   * Process:
   * 1. Check localStorage for saved theme
   * 2. If saved theme exists, apply it
   * 3. If no saved theme, detect system preference
   * 4. Apply detected theme
   */
  private initializeTheme(): void {
    // Check if user has a saved preference
    const savedTheme = localStorage.getItem('theme');
    
    if (savedTheme) {
      this.setDarkMode(savedTheme === 'dark');
    } else {
      // Check system preference using media query
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      this.setDarkMode(prefersDark);
    }
  }

  /**
   * Set dark mode state and apply theme
   * 
   * Updates the theme state, applies CSS classes to the document,
   * and persists the preference to localStorage.
   * 
   * @param isDark - Whether to enable dark mode
   * 
   * @example
   * this.setDarkMode(true);  // Enable dark mode
   * this.setDarkMode(false); // Enable light mode
   */
  private setDarkMode(isDark: boolean): void {
    // Update reactive state
    this.isDarkMode.next(isDark);
    
    // Apply CSS classes to document
    const element = document.querySelector('html');
    
    if (isDark) {
      element?.classList.add('my-app-dark');
      element?.classList.remove('surface-50');
    } else {
      element?.classList.remove('my-app-dark');
      element?.classList.add('surface-50');
    }
    
    // Persist preference to localStorage
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
  }
} 