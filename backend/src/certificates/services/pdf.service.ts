import { Injectable, Logger } from '@nestjs/common';
import * as puppeteer from 'puppeteer';
import * as path from 'path';
import * as fs from 'fs';

/**
 * PDF Service
 * 
 * Servizio per la generazione di PDF da template HTML per i certificati.
 * Utilizza Puppeteer per convertire template HTML in PDF con design professionale.
 * 
 * Features:
 * - Generazione PDF da template HTML
 * - Template personalizzabili per diversi tipi di certificati
 * - Supporto per variabili dinamiche nei template
 * - Configurazione avanzata per layout e formattazione
 * - Gestione errori e logging completo
 * 
 * Template System:
 * - Template HTML memorizzati in 'src/certificates/templates/'
 * - Sostituzione variabili con sintassi {{variableName}}
 * - Supporto per CSS personalizzati
 * - Layout responsive per diversi formati
 * 
 * Usage:
 * - Iniettato nel CertificatesService per generazione automatica PDF
 * - Fornisce metodi per generare PDF da dati certificato
 * - Gestisce configurazione Puppeteer e rendering
 * 
 * @example
 * // Genera PDF certificato
 * const pdfBuffer = await this.pdfService.generateCertificatePDF({
 *   studentName: 'Mario Rossi',
 *   courseName: 'TypeScript Avanzato',
 *   issuedDate: '2024-01-15',
 *   certificateId: 'cert-123'
 * });
 */
@Injectable()
export class PdfService {
  private readonly logger = new Logger(PdfService.name);
  private browser: puppeteer.Browser | null = null;

  // ============================================================================
  // BROWSER MANAGEMENT
  // ============================================================================

  /**
   * Inizializza browser Puppeteer
   * 
   * Crea e configura un'istanza browser per la generazione PDF.
   * Gestisce la configurazione per ambienti Docker e locali.
   * 
   * @returns Promise con browser configurato
   */
  private async getBrowser(): Promise<puppeteer.Browser> {
    if (!this.browser) {
      this.logger.debug('Initializing Puppeteer browser');
      
      const launchOptions: puppeteer.LaunchOptions = {
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu'
        ]
      };

      // Configurazione per ambiente Docker
      if (process.env.NODE_ENV === 'production') {
        launchOptions.executablePath = '/usr/bin/google-chrome-stable';
      }

      this.browser = await puppeteer.launch(launchOptions);
      this.logger.log('Puppeteer browser initialized successfully');
    }

    return this.browser;
  }

  /**
   * Chiude browser Puppeteer
   * 
   * Pulisce le risorse browser quando il servizio viene distrutto.
   */
  async closeBrowser(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.logger.log('Puppeteer browser closed');
    }
  }

  // ============================================================================
  // TEMPLATE MANAGEMENT
  // ============================================================================

  /**
   * Ottiene il percorso della directory templates
   * 
   * @returns Percorso assoluto alla directory templates
   */
  private getTemplatesPath(): string {
    return path.join(process.cwd(), 'src', 'certificates', 'templates');
  }

  /**
   * Carica template HTML per certificato
   * 
   * @param templateName - Nome del template (senza estensione)
   * @returns Contenuto del template HTML
   */
  private async loadTemplate(templateName: string): Promise<string> {
    const templatePath = path.join(this.getTemplatesPath(), `${templateName}.html`);
    
    try {
      const template = await fs.promises.readFile(templatePath, 'utf-8');
      this.logger.debug(`Template loaded: ${templateName}`);
      return template;
    } catch (error) {
      this.logger.error(`Failed to load template: ${templateName}`, error);
      throw new Error(`Template not found: ${templateName}`);
    }
  }

  /**
   * Sostituisce variabili nel template HTML
   * 
   * @param template - Template HTML con variabili {{variableName}}
   * @param variables - Oggetto con variabili da sostituire
   * @returns Template HTML con variabili sostituite
   */
  private replaceVariables(template: string, variables: Record<string, any>): string {
    let processedTemplate = template;
    
    // Sostituisce tutte le variabili nel formato {{variableName}}
    Object.entries(variables).forEach(([key, value]) => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      processedTemplate = processedTemplate.replace(regex, String(value || ''));
    });

    this.logger.debug('Template variables replaced', { 
      variablesCount: Object.keys(variables).length 
    });

    return processedTemplate;
  }

  // ============================================================================
  // PDF GENERATION
  // ============================================================================

  /**
   * Genera PDF certificato da template HTML
   * 
   * Crea un PDF professionale per certificato utilizzando template HTML
   * e configurazione Puppeteer ottimizzata per documenti formali.
   * 
   * Process:
   * 1. Carica template HTML per certificato
   * 2. Sostituisce variabili con dati certificato
   * 3. Inizializza browser Puppeteer
   * 4. Crea pagina e carica HTML
   * 5. Genera PDF con configurazione ottimizzata
   * 6. Restituisce buffer PDF
   * 
   * @param certificateData - Dati certificato per popolare template
   * @returns Promise con buffer PDF generato
   * 
   * @throws Error se generazione PDF fallisce
   */
  async generateCertificatePDF(certificateData: {
    studentName: string;
    courseName: string;
    issuedDate: string;
    certificateId: string;
    description?: string;
    organizationName?: string;
    instructorName?: string;
  }): Promise<Buffer> {
    this.logger.log('Starting PDF certificate generation', {
      studentName: certificateData.studentName,
      courseName: certificateData.courseName,
      certificateId: certificateData.certificateId
    });

    try {
      // 1. Carica template HTML
      const template = await this.loadTemplate('certificate');
      
      // 2. Prepara variabili per template
      const variables = {
        studentName: certificateData.studentName,
        courseName: certificateData.courseName,
        issuedDate: this.formatDate(certificateData.issuedDate),
        certificateId: certificateData.certificateId,
        description: certificateData.description || '',
        organizationName: certificateData.organizationName || 'ReturnCode Academy',
        instructorName: certificateData.instructorName || 'Docente Certificato',
        currentYear: new Date().getFullYear()
      };

      // 3. Sostituisce variabili nel template
      const htmlContent = this.replaceVariables(template, variables);

      // 4. Inizializza browser
      const browser = await this.getBrowser();
      const page = await browser.newPage();

      try {
        // 5. Configura pagina per PDF
        await page.setViewport({ width: 1200, height: 800 });
        await page.setContent(htmlContent, { 
          waitUntil: 'networkidle0',
          timeout: 30000 
        });

        // 6. Genera PDF con configurazione ottimizzata
        const pdfBuffer = await page.pdf({
          format: 'A4',
          printBackground: true,
          margin: {
            top: '20mm',
            right: '20mm',
            bottom: '20mm',
            left: '20mm'
          },
          displayHeaderFooter: false,
          preferCSSPageSize: true
        });

        this.logger.log('PDF certificate generated successfully', {
          certificateId: certificateData.certificateId,
          pdfSize: pdfBuffer.length
        });

        return Buffer.from(pdfBuffer);

      } finally {
        // Chiude pagina per liberare risorse
        await page.close();
      }

    } catch (error) {
      this.logger.error('PDF certificate generation failed', {
        error: error.message,
        stack: error.stack,
        certificateId: certificateData.certificateId
      });
      throw new Error(`PDF generation failed: ${error.message}`);
    }
  }

  /**
   * Formatta data per visualizzazione
   * 
   * @param dateString - Data in formato ISO o stringa
   * @returns Data formattata per visualizzazione
   */
  private formatDate(dateString: string): string {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('it-IT', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch (error) {
      this.logger.warn('Invalid date format, using original string', { dateString });
      return dateString;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Verifica se template esiste
   * 
   * @param templateName - Nome template da verificare
   * @returns True se template esiste
   */
  async templateExists(templateName: string): Promise<boolean> {
    try {
      const templatePath = path.join(this.getTemplatesPath(), `${templateName}.html`);
      await fs.promises.access(templatePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Lista template disponibili
   * 
   * @returns Array con nomi template disponibili
   */
  async listTemplates(): Promise<string[]> {
    try {
      const templatesPath = this.getTemplatesPath();
      const files = await fs.promises.readdir(templatesPath);
      return files
        .filter(file => file.endsWith('.html'))
        .map(file => file.replace('.html', ''));
    } catch (error) {
      this.logger.error('Failed to list templates', error);
      return [];
    }
  }
}
