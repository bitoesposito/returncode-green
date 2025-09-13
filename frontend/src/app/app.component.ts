import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ImageModule } from 'primeng/image';
import { MessageService } from 'primeng/api';
import { ConfirmationService } from 'primeng/api';
import { TranslateModule, TranslateService } from '@ngx-translate/core';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    RouterOutlet,
    ImageModule,
    TranslateModule
  ],
  providers: [
    MessageService,
    ConfirmationService
  ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent implements OnInit {
  title = 'frontend';

  constructor(
    private translate: TranslateService
  ) {
    // Initialize translations - removed as it's now handled by LanguageService
    // translate.setDefaultLang('en-US');
    // translate.use('en-US');
  }

  async ngOnInit() {
    // PWA services are automatically initialized in the constructor
  }
}
