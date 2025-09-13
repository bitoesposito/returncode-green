import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormArray, FormControl, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { TranslateModule } from '@ngx-translate/core';
import { ButtonModule } from 'primeng/button';
import { MessageService } from 'primeng/api';
import { ToastModule } from 'primeng/toast';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { CertificateService, GenerateCertificateRequest } from '../../services/certificate.service';
import { CookieAuthService } from '../../services/cookie-auth.service';

@Component({
  selector: 'app-quiz',
  imports: [
    ReactiveFormsModule,
    TranslateModule,
    CommonModule,
    FormsModule,
    ButtonModule,
    RouterModule,
    ToastModule,
    ProgressSpinnerModule
  ],
  templateUrl: './quiz.component.html',
  styleUrl: './quiz.component.scss',
  providers: [MessageService]
})
export class QuizComponent implements OnInit {
  
  isLoading = false;
  currentUser: any = null;

  constructor(
    public router: Router,
    private certificateService: CertificateService,
    private authService: CookieAuthService,
    private messageService: MessageService
  ) {}

  ngOnInit() {
    // Ottieni l'utente corrente
    this.authService.getCurrentUser().subscribe({
      next: (response: any) => {
        if (response.success && response.data?.user) {
          this.currentUser = response.data.user;
        }
      },
      error: (error: any) => {
        console.error('Errore nel recupero utente:', error);
        this.messageService.add({
          severity: 'error',
          summary: 'Errore',
          detail: 'Impossibile recuperare i dati utente'
        });
      }
    });
  }

  /**
   * Genera certificato per il corso completato
   */
  generateCertificate() {
    if (!this.currentUser) {
      this.messageService.add({
        severity: 'error',
        summary: 'Errore',
        detail: 'Utente non trovato'
      });
      return;
    }

    this.isLoading = true;

    const certificateData: GenerateCertificateRequest = {
      user_uuid: this.currentUser.uuid,
      course_name: 'TypeScript Fundamentals Course',
      description: 'Corso completo sui fondamenti di TypeScript, incluse le funzionalità avanzate e le best practices per lo sviluppo moderno.',
      issued_date: new Date().toISOString(),
      metadata: {
        course_type: 'online',
        difficulty_level: 'intermediate',
        completion_score: 100,
        duration_hours: 20,
        instructor: 'ReturnCode Academy',
        quiz_score: '10/10',
        completion_date: new Date().toISOString()
      }
    };

    this.certificateService.generateCertificate(certificateData).subscribe({
      next: (certificate) => {
        this.isLoading = false;
        this.messageService.add({
          severity: 'success',
          summary: 'Certificato Generato!',
          detail: `Il tuo certificato "${certificate.course_name}" è stato generato con successo.`
        });
        
        // Opzionale: scarica automaticamente il certificato
        setTimeout(() => {
          this.downloadCertificate(certificate.id);
        }, 2000);
      },
      error: (error) => {
        this.isLoading = false;
        console.error('Errore nella generazione certificato:', error);
        this.messageService.add({
          severity: 'error',
          summary: 'Errore',
          detail: 'Impossibile generare il certificato. Riprova più tardi.'
        });
      }
    });
  }

  /**
   * Scarica il certificato generato
   */
  private downloadCertificate(certificateId: string) {
    this.certificateService.downloadCertificateFile(certificateId);
  }
}
