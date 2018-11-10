import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, Validators } from '@angular/forms';

import { PostsService } from '../posts.service';
import { Post } from '../post.model';
import { ActivatedRoute, ParamMap } from '@angular/router';
import { mimeType } from './mime-type.validator';

@Component({
  selector: 'app-post-create',
  templateUrl: './post-create.component.html',
  styleUrls: ['./post-create.component.css']
})

export class PostCreateComponent implements OnInit {
  enteredTitle = '';
  enteredContent = '';
  post: Post;
  isLoading = false;
  form: FormGroup;
  imagePreview: string;

  private mode = 'create';
  private postId: string;

  constructor(public postsService: PostsService, public route: ActivatedRoute) {}

  ngOnInit() {
    this.form = new FormGroup({
      'title': new FormControl( null, {validators: [Validators.required, Validators.minLength(3)]} ),
      'content': new FormControl( null, {validators: [Validators.required]} ),
      'image': new FormControl( null, {validators: [Validators.required], asyncValidators: [mimeType]} )
    });

    this.route.paramMap.subscribe((paramMap: ParamMap) => {
      if (paramMap.has('postId')) {
        this.mode = 'edit';
        this.postId = paramMap.get('postId');
        console.log('EDIT MODE ' + this.postId);
        this.isLoading = true;
        this.postsService.getPost(this.postId).subscribe( postData => {
          // IMAGE FILE IS NULL HERE - THAT'S THE PROBLEM - FIX IT AND THINGS WILL BE BETTER
          console.log('GOT POST: ' + postData.title + ' ' + postData.image);
          this.isLoading = false;
          // SMM THERE IS A PROBLEM WITH id - COURSE CALLS IT _id AND I'VE MISSED SOMETHING SOMEWHERE
          this.post = {id: postData.id, title: postData.title, content: postData.content, imagePath: postData.image };
          this.form.setValue({
            title: this.post.title,
            content: this.post.content,
            // THIS NEXT LINE BREAKS EDITING BADLY
            // THROWS AN ERROR BECAUSE THIS IS UNSET - SO IT MAY BE TOTALLY WRONG
            // image: this.post.imagePath
            // SETTING IMAGE TO NULL WORKS FINE
            image: ''
          });
          this.imagePreview = this.post.imagePath;  // SMM TEST
          console.log('IMAGE ' + postData.image + ' ' + postData.title);
        });
      } else {
        console.log('*** CREATE POST');
        this.mode = 'create';
        this.postId = null;
      }
    });
  }

  onImagePicked(event: Event) {
    const file = (event.target as HTMLInputElement).files[0];
    this.form.patchValue({image: file});
    this.form.get('image').updateValueAndValidity();
    console.log('IMAGE PICKED: ' + file);
    const reader = new FileReader();
    reader.onload = () => {
      this.imagePreview = <string>reader.result;
      console.log('IMAGE ONLOAD: ' + reader.result);
    };
    reader.readAsDataURL(file);
  }

  onSavePost() {
    if (this.form.invalid) {
      return;
    }
    this.isLoading = true;
    if (this.mode === 'create') {
      this.postsService.addPost(this.form.value.title, this.form.value.content, this.form.value.image);
    } else {
      console.log(this.form.value.title + ' ' + this.form.value.content);
      this.postsService.updatePost(this.postId, this.form.value.title, this.form.value.content, this.form.value.image);
    }
    this.form.reset();
  }
}
