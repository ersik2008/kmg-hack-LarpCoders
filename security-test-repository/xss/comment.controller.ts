import { Request, Response } from 'express';

export class CommentController {
  renderComment(req: Request, res: Response) {
    const comment = req.query.comment as string;
    // VULNERABLE: Direct rendering of unsanitized user comment into HTML response
    res.send(`<div class="comment-box"><p>${comment}</p></div>`);
  }
}
