import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { map } from 'rxjs/operators';

import { Post } from './post.model';
import { Router } from '@angular/router';

@Injectable({providedIn: 'root'})
export class PostsService {
  private posts: Post[] = [];
  private postsUpdated = new Subject<Post[]>();

  constructor (private http: HttpClient, private router: Router) {}

  getPosts() {
    this.http.get<{message: string, posts: any }>('http://localhost:3000/api/posts')
      .pipe(map( (postData) => {
        return postData.posts.map( post => {
            return {
              title: post.title,
              content: post.content,
              id: post._id,
              imagePath: post.imagePath
            };
        });
      }))
      .subscribe((transformedPosts) => {
        this.posts = transformedPosts;
        this.postsUpdated.next([...this.posts]);
      });
  }

  getPostUpdateListener() {
    console.log('TRIGGERED GETPOSTLISTENER');
    return this.postsUpdated.asObservable();
  }

  getPost(id: string) {
    console.log('CALLING GETPOST: ' + id);
    return this.http.get<{id: string, title: string, content: string, image: string }>('http://localhost:3000/api/posts/' + id);
  }

  addPost(title: string, content: string, image: File) {
    const postData = new FormData();
    postData.append('title', title);
    postData.append('content', content);
    postData.append('image', image, title);

    this.http
      .post<{message: string, post: Post}>('http://localhost:3000/api/posts', postData)
      .subscribe((responseData) => {
        const post: Post = {
          id: responseData.post.id,
          title: responseData.post.title,
          content: responseData.post.content,
          imagePath: responseData.post.imagePath
        };
        this.posts.push(post);
        this.postsUpdated.next([...this.posts]);
        this.router.navigate(['/']);
    });
  }

  updatePost(id: string, title: string, content: string, image: File | string ) {
    console.log('CALLING UPDATEPOST');
    let postData: Post | FormData;
    if (typeof(image) === 'object') {
      console.log('ITS AN OBJECT');
      postData = new FormData();
      postData.append('title', title);
      postData.append('content', content);
      postData.append('image', image, title);
    } else {
      console.log('NOT AN OBJECT - STRING');
      // IT'S A STRING, SO JUST UPDATE THE JSON
      postData = { id: id, title: title, content: content, imagePath: image };
    }

    this.http.put('http://localhost:3000/api/posts/' + id, postData)
    .subscribe(response => {
      const updatedPosts = [...this.posts];
      const oldPostIndex = updatedPosts.findIndex(p => p.id === id);
      const post: Post = { id: id, title: title, content: content, imagePath: '' };
      updatedPosts[oldPostIndex] = post;
      this.posts = updatedPosts;
      console.log('GOT RESPONSE FROM UPDATEPOST ' + oldPostIndex);
      this.postsUpdated.next([...this.posts]);
      this.router.navigate(['/']);
    });
  }

  deletePost(postId: string) {
    console.log('HIT DELETEPOST');
    this.http.delete('http://localhost:3000/api/posts/' + postId)
    .subscribe(() => {
      const updatedPosts = this.posts.filter(post => post.id !== postId);
      this.posts = updatedPosts;
      this.postsUpdated.next([...this.posts]);
    });
  }
}
