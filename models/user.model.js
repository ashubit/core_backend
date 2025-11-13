module.exports = mongoose => {
    const User = mongoose.model(
      "users",
      mongoose.Schema(
        {
          username: String,
          email: { type: String, required: true, unique: true },
          // do not return pwd by default from queries
          pwd: { type: String, select: false },
          mobile: String,
          gender: String,
          address: String,
          dob: String,
          country: String,
          state: String,
          pincode: String,
          status: Boolean,
          role: {
            type: String,
            enum: ['user', 'admin'],
            default: 'user'
          }
        },
        { timestamps: true }
      ).method("toJSON", function() {
        // remove sensitive fields when converting to JSON
        const { __v, _id, pwd, ...object } = this.toObject();
        object.id = _id;
        return object;
      })
    );

    return User;
  };