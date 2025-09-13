import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

/**
 * Servizio per gestire il fullscreen obbligatorio durante i quiz
 * Previene comportamenti scorretti monitorando lo stato fullscreen
 */
@Injectable({
  providedIn: 'root'
})
export class FullscreenService {
  private isFullscreenSubject = new BehaviorSubject<boolean>(false);
  private isFullscreenRequiredSubject = new BehaviorSubject<boolean>(false);
  
  public isFullscreen$: Observable<boolean> = this.isFullscreenSubject.asObservable();
  public isFullscreenRequired$: Observable<boolean> = this.isFullscreenRequiredSubject.asObservable();

  constructor() {
    // Monitora i cambiamenti di fullscreen
    this.setupFullscreenListeners();
  }

  /**
   * Configura i listener per monitorare i cambiamenti di fullscreen
   */
  private setupFullscreenListeners(): void {
    // Listener per il cambio di fullscreen
    document.addEventListener('fullscreenchange', () => {
      this.updateFullscreenStatus();
    });

    // Listener per quando l'utente esce dal fullscreen (ESC, F11, etc.)
    document.addEventListener('fullscreenerror', () => {
      this.updateFullscreenStatus();
    });

    // Listener per il resize della finestra (può indicare uscita da fullscreen)
    window.addEventListener('resize', () => {
      this.updateFullscreenStatus();
    });

    // Listener per il focus/blur della finestra
    window.addEventListener('blur', () => {
      if (this.isFullscreenRequiredSubject.value) {
        this.updateFullscreenStatus();
      }
    });

    window.addEventListener('focus', () => {
      if (this.isFullscreenRequiredSubject.value) {
        this.updateFullscreenStatus();
      }
    });
  }

  /**
   * Aggiorna lo stato del fullscreen
   */
  private updateFullscreenStatus(): void {
    const isFullscreen = this.checkFullscreenStatus();
    this.isFullscreenSubject.next(isFullscreen);
  }

  /**
   * Verifica se il browser è attualmente in modalità fullscreen
   */
  private checkFullscreenStatus(): boolean {
    return !!(
      document.fullscreenElement ||
      (document as any).webkitFullscreenElement ||
      (document as any).mozFullScreenElement ||
      (document as any).msFullscreenElement
    );
  }

  /**
   * Richiede l'attivazione del fullscreen
   */
  async requestFullscreen(): Promise<boolean> {
    try {
      const element = document.documentElement;
      
      if (element.requestFullscreen) {
        await element.requestFullscreen();
      } else if ((element as any).webkitRequestFullscreen) {
        await (element as any).webkitRequestFullscreen();
      } else if ((element as any).mozRequestFullScreen) {
        await (element as any).mozRequestFullScreen();
      } else if ((element as any).msRequestFullscreen) {
        await (element as any).msRequestFullscreen();
      } else {
        throw new Error('Fullscreen non supportato da questo browser');
      }

      this.updateFullscreenStatus();
      return true;
    } catch (error) {
      console.error('Errore nell\'attivazione del fullscreen:', error);
      return false;
    }
  }

  /**
   * Esce dal fullscreen
   */
  async exitFullscreen(): Promise<boolean> {
    try {
      if (document.exitFullscreen) {
        await document.exitFullscreen();
      } else if ((document as any).webkitExitFullscreen) {
        await (document as any).webkitExitFullscreen();
      } else if ((document as any).mozCancelFullScreen) {
        await (document as any).mozCancelFullScreen();
      } else if ((document as any).msExitFullscreen) {
        await (document as any).msExitFullscreen();
      }

      this.updateFullscreenStatus();
      return true;
    } catch (error) {
      console.error('Errore nell\'uscita dal fullscreen:', error);
      return false;
    }
  }

  /**
   * Attiva la modalità fullscreen obbligatoria
   */
  enableRequiredFullscreen(): void {
    this.isFullscreenRequiredSubject.next(true);
    this.updateFullscreenStatus();
  }

  /**
   * Disattiva la modalità fullscreen obbligatoria
   */
  disableRequiredFullscreen(): void {
    this.isFullscreenRequiredSubject.next(false);
    this.exitFullscreen();
  }

  /**
   * Verifica se il fullscreen è attualmente richiesto
   */
  get isFullscreenRequired(): boolean {
    return this.isFullscreenRequiredSubject.value;
  }

  /**
   * Verifica se il browser è attualmente in fullscreen
   */
  get isCurrentlyFullscreen(): boolean {
    return this.isFullscreenSubject.value;
  }
}
