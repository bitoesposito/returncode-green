export interface Language {
  name: string;
  code: string;
  flag: string;
}

export interface LanguageChangeEvent {
  value: string;
  originalEvent?: Event;
} 