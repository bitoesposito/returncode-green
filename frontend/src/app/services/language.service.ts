import { Injectable } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Language } from '../models/language.models';
import { ApplicationRef } from '@angular/core';
import { map } from 'rxjs/operators';

/**
 * Language Service
 * 
 * Manages application internationalization (i18n) and language switching
 * functionality. Provides comprehensive language management including
 * language selection, persistence, and reactive language state updates.
 * 
 * Features:
 * - Multi-language support (English, Italian)
 * - Language persistence in localStorage
 * - Reactive language state management
 * - Language validation and fallback
 * - Application-wide language switching
 * - Flag icons for language selection
 * - Default language fallback
 * 
 * Supported Languages:
 * - English (en-US) - Default language
 * - Italian (it-IT) - Secondary language
 * 
 * Language Management:
 * - Automatic language detection and loading
 * - Persistent language preferences
 * - Validation of language codes
 * - Graceful fallback to default language
 * - Application-wide change detection
 * 
 * Usage:
 * - Inject service in components
 * - Subscribe to currentLanguage$ for reactive updates
 * - Call setLanguage() to change language
 * - Use getCurrentLanguageObject() for language metadata
 * 
 * @example
 * // Change language
 * this.languageService.setLanguage('it-IT');
 * 
 * @example
 * // Subscribe to language changes
 * this.languageService.currentLanguage$.subscribe(lang => {
 *   console.log('Current language:', lang);
 * });
 * 
 * @example
 * // Get current language object
 * const currentLang = this.languageService.getCurrentLanguageObject();
 * console.log('Language name:', currentLang?.name);
 * console.log('Language flag:', currentLang?.flag);
 */
@Injectable({
  providedIn: 'root'
})
export class LanguageService {
  // ============================================================================
  // PROPERTIES
  // ============================================================================

  /**
   * LocalStorage key for saving language preference
   */
  private readonly STORAGE_KEY = 'selectedLanguage';

  /**
   * Default language code used as fallback
   */
  private readonly DEFAULT_LANGUAGE = 'en-US';
  
  /**
   * Available languages configuration
   * 
   * Defines all supported languages with their metadata
   * including name, code, and flag icon path.
   */
  private availableLanguages: Language[] = [
    {
      name: 'English',
      code: 'en-US',
      flag: './assets/flags/US.png'
    },
    {
      name: 'Italiano',
      code: 'it-IT',
      flag: './assets/flags/IT.png'
    }
  ];

  /**
   * BehaviorSubject for current language state
   * Provides reactive updates when language changes
   */
  private currentLanguageSubject = new BehaviorSubject<string>(this.DEFAULT_LANGUAGE);

  /**
   * Observable for current language state
   * Subscribe to this for reactive language updates
   */
  public currentLanguage$ = this.currentLanguageSubject.asObservable();

  // ============================================================================
  // CONSTRUCTOR
  // ============================================================================

  constructor(
    private translate: TranslateService,
    private appRef: ApplicationRef
  ) {
    this.initializeLanguage();
  }

  // ============================================================================
  // INITIALIZATION METHODS
  // ============================================================================

  /**
   * Initialize the language service
   * 
   * Sets up the translation service with available languages,
   * loads saved language preference, and configures default language.
   * 
   * Initialization process:
   * 1. Add available languages to translation service
   * 2. Set default language
   * 3. Load saved language preference
   * 4. Apply language setting
   */
  private initializeLanguage(): void {
    // Set available languages in translation service
    this.translate.addLangs(['en-US', 'it-IT']);
    
    // Set default language for fallback
    this.translate.setDefaultLang(this.DEFAULT_LANGUAGE);
    
    // Load saved language or use default
    const savedLanguage = this.getSavedLanguage();
    this.setLanguage(savedLanguage);
  }

  // ============================================================================
  // LANGUAGE RETRIEVAL METHODS
  // ============================================================================

  /**
   * Get all available languages
   * 
   * Returns a copy of the available languages array
   * to prevent external modification.
   * 
   * @returns Array of available language objects
   * 
   * @example
   * const languages = this.getAvailableLanguages();
   * languages.forEach(lang => {
   *   console.log(`${lang.name} (${lang.code})`);
   * });
   */
  getAvailableLanguages(): Language[] {
    return [...this.availableLanguages];
  }

  /**
   * Get current language code
   * 
   * Returns the currently active language code.
   * 
   * @returns Current language code (e.g., 'en-US', 'it-IT')
   * 
   * @example
   * const currentLang = this.getCurrentLanguage();
   * console.log('Current language:', currentLang); // 'en-US'
   */
  getCurrentLanguage(): string {
    return this.currentLanguageSubject.value;
  }

  /**
   * Get language object by code
   * 
   * Retrieves the language object for a specific language code.
   * 
   * @param code - Language code to look up
   * @returns Language object or undefined if not found
   * 
   * @example
   * const italian = this.getLanguageByCode('it-IT');
   * console.log('Italian name:', italian?.name); // 'Italiano'
   * console.log('Italian flag:', italian?.flag); // './assets/flags/IT.png'
   */
  getLanguageByCode(code: string): Language | undefined {
    return this.availableLanguages.find(lang => lang.code === code);
  }

  /**
   * Get current language object
   * 
   * Retrieves the language object for the currently active language.
   * 
   * @returns Current language object or undefined if not found
   * 
   * @example
   * const currentLang = this.getCurrentLanguageObject();
   * if (currentLang) {
   *   console.log('Language:', currentLang.name);
   *   console.log('Flag:', currentLang.flag);
   * }
   */
  getCurrentLanguageObject(): Language | undefined {
    return this.getLanguageByCode(this.getCurrentLanguage());
  }

  /**
   * Get current language object as observable
   * 
   * Returns an observable that emits the current language object
   * whenever the language changes.
   * 
   * @returns Observable of current language object
   * 
   * @example
   * this.getCurrentLanguageObject$().subscribe(lang => {
   *   if (lang) {
   *     console.log('Language changed to:', lang.name);
   *   }
   * });
   */
  getCurrentLanguageObject$(): Observable<Language | undefined> {
    return this.currentLanguage$.pipe(
      map(languageCode => this.getLanguageByCode(languageCode))
    );
  }

  /**
   * Get current language name
   * 
   * Returns the display name of the currently active language.
   * 
   * @returns Current language name or 'English' as fallback
   * 
   * @example
   * const langName = this.getCurrentLanguageName();
   * console.log('Current language:', langName); // 'English' or 'Italiano'
   */
  getCurrentLanguageName(): string {
    const currentLang = this.getCurrentLanguageObject();
    return currentLang ? currentLang.name : 'English';
  }

  // ============================================================================
  // LANGUAGE SETTING METHODS
  // ============================================================================

  /**
   * Set language and save to storage
   * 
   * Changes the application language, updates the translation service,
   * saves the preference to localStorage, and triggers change detection.
   * 
   * @param languageCode - Language code to set (e.g., 'en-US', 'it-IT')
   * 
   * @example
   * this.setLanguage('it-IT');
   * // Application language changes to Italian
   * 
   * Process:
   * 1. Validates language code
   * 2. Updates translation service
   * 3. Updates reactive state
   * 4. Saves to localStorage
   * 5. Triggers change detection
   */
  setLanguage(languageCode: string): void {
    // Validate language code
    if (!this.isValidLanguage(languageCode)) {
      languageCode = this.DEFAULT_LANGUAGE;
    }

    // Set the language in translation service
    this.translate.use(languageCode);
    
    // Update reactive state
    this.currentLanguageSubject.next(languageCode);
    
    // Save to localStorage for persistence
    this.saveLanguage(languageCode);
    
    // Force application-wide change detection
    setTimeout(() => {
      this.appRef.tick();
    }, 100);
  }

  /**
   * Change language (alias for setLanguage)
   * 
   * Convenience method for changing the application language.
   * 
   * @param languageCode - Language code to change to
   * 
   * @example
   * this.changeLanguage('it-IT');
   * // Same as this.setLanguage('it-IT')
   */
  changeLanguage(languageCode: string): void {
    this.setLanguage(languageCode);
  }

  /**
   * Reset to default language
   * 
   * Resets the application language to the default language
   * and clears any saved preference.
   * 
   * @example
   * this.resetToDefault();
   * // Language resets to English (en-US)
   */
  resetToDefault(): void {
    this.setLanguage(this.DEFAULT_LANGUAGE);
  }

  // ============================================================================
  // STORAGE METHODS
  // ============================================================================

  /**
   * Get saved language from localStorage
   * 
   * Retrieves the saved language preference from localStorage
   * with validation and fallback to default language.
   * 
   * @returns Saved language code or default language
   * 
   * Error handling:
   * - Catches localStorage access errors
   * - Falls back to default language on error
   * - Validates saved language code
   */
  private getSavedLanguage(): string {
    try {
      const saved = localStorage.getItem(this.STORAGE_KEY);
      return saved && this.isValidLanguage(saved) ? saved : this.DEFAULT_LANGUAGE;
    } catch (error) {
      return this.DEFAULT_LANGUAGE;
    }
  }

  /**
   * Save language to localStorage
   * 
   * Persists the current language preference to localStorage
   * for future application sessions.
   * 
   * @param languageCode - Language code to save
   * 
   * Error handling:
   * - Catches localStorage write errors
   * - Logs warnings on storage failures
   * - Continues operation even if storage fails
   */
  private saveLanguage(languageCode: string): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, languageCode);
    } catch (error) {
    }
  }

  /**
   * Clear saved language preference
   * 
   * Removes the saved language preference from localStorage,
   * causing the application to use the default language on next load.
   * 
   * @example
   * this.clearSavedLanguage();
   * // Next app load will use default language
   * 
   * Error handling:
   * - Catches localStorage removal errors
   * - Logs warnings on storage failures
   */
  clearSavedLanguage(): void {
    try {
      localStorage.removeItem(this.STORAGE_KEY);
    } catch (error) {
    }
  }

  // ============================================================================
  // VALIDATION METHODS
  // ============================================================================

  /**
   * Check if language code is valid
   * 
   * Validates that a language code is supported by the application.
   * 
   * @param languageCode - Language code to validate
   * @returns True if language is supported, false otherwise
   * 
   * @example
   * if (this.isValidLanguage('it-IT')) {
   *   console.log('Italian is supported');
   * }
   * 
   * @example
   * if (this.isValidLanguage('fr-FR')) {
   *   console.log('French is supported');
   * } else {
   *   console.log('French is not supported');
   * }
   */
  private isValidLanguage(languageCode: string): boolean {
    return this.availableLanguages.some(lang => lang.code === languageCode);
  }
} 