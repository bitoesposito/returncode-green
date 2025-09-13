import { bootstrapApplication } from '@angular/platform-browser';
import { enableProdMode } from '@angular/core';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';

// Abilita modalità produzione per rimuovere i log di debug
// enableProdMode();

bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));
