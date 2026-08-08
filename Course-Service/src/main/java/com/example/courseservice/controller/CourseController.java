package com.example.courseservice.controller;

import com.example.courseservice.model.Course;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    private final List<Course> courses = new ArrayList<>();
    private final AtomicLong idCounter = new AtomicLong(1);

    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ')")
    public List<Course> getAllCourses() {
        return courses;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public Course createCourse(@RequestBody Course course) {
        course.setId(idCounter.getAndIncrement());
        courses.add(course);
        return course;
    }
}
