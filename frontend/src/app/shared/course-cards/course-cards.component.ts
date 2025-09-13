import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';

/**
 * Course Cards Component
 * 
 * Displays static course information in a card format.
 */
@Component({
  selector: 'app-course-cards',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule
  ],
  templateUrl: './course-cards.component.html',
  styleUrl: './course-cards.component.scss'
})
export class CourseCardsComponent {

  constructor(
    public router: Router
  ) {}

  onCourseClick() {
    this.router.navigate(['/quiz']);
  }
}


