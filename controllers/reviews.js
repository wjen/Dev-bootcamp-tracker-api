const ErrorResponse = require("../utils/errorResponse.js");
const asyncHandler = require("../middleware/aysnc");
const Review = require("../models/Review");
const Bootcamp = require("../models/Bootcamp");

// @desc Get reviews
// @route GET /api/v1/reviews
// @route GET /api/v1/bootcamps/:bootcampId/reviews
exports.getReviews = asyncHandler(async (req, res, next) => {
  if (req.params.bootcampId) {
    const reviews = await Review.find({ bootcamp: req.params.bootcampId });
    res.status(200).json({
      success: true,
      count: reviews.length,
      data: reviews,
    });
  } else {
    res.status(200).json(res.advancedResults);
  }
});

// @desc Get a review
// @route GET /api/v1/reviews/:id
exports.getReview = asyncHandler(async (req, res, next) => {
  const review = await Review.findById(req.params.id).populate({
    path: "bootcamp",
    select: "name description",
  });

  if (!review) {
    return next(
      new ErrorResponse(`No review found with the id of ${req.params.id}`, 404)
    );
  }
  res.status(200).json({
    success: true,
    data: review,
  });
});

// @desc Add a review
// @route POST /api/v1/bootcamps/:bootcampId/review
// @access Private
exports.addReview = asyncHandler(async (req, res, next) => {
  req.body.bootcamp = req.params.bootcampId;
  req.body.user = req.user.id;

  const bootcamp = await Bootcamp.findById(req.params.bootcampId);

  if (!bootcamp) {
    return next(
      new ErrorResponse(
        `No bootcamp with id ${req.params.bootcampId} found`,
        404
      )
    );
  }
  const review = await Review.create(req.body);
  res.status(200).json({
    success: true,
    data: review,
  });
});

// @desc Update a review
// @route PUT /api/v1/reviews/:id
// @access Private
exports.updateReview = asyncHandler(async (req, res, next) => {
  let review = await Review.findById(req.params.id);

  if (!review) {
    return next(
      new ErrorResponse(`No review with id ${req.params.id} found`, 404)
    );
  }

  // Make sure review belongs to user or user is admin
  // convert objectid to string to make comparison
  if (req.user.id !== review.user.toString() && req.user.role !== "admin") {
    return next(new ErrorResponse("Not authorized to update review", 401));
  }
  review = await Review.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });
  res.status(200).json({
    success: true,
    data: review,
  });
});

// @desc Delete a review
// @route DELETE /api/v1/reviews/:id
// @access Private
exports.deleteReview = asyncHandler(async (req, res, next) => {
  let review = await Review.findById(req.params.id);

  if (!review) {
    return next(
      new ErrorResponse(`No review with id ${req.params.id} found`, 404)
    );
  }

  // Make sure review belongs to user or user is admin
  // convert objectid to string to make comparison
  if (req.user.id !== review.user.toString() && req.user.role !== "admin") {
    return next(new ErrorResponse("Not authorized to delete review", 401));
  }
  await review.remove();
  res.status(200).json({
    success: true,
    data: {},
  });
});
