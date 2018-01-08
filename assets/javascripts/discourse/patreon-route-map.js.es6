export default {
  resource: 'admin.adminPlugins',
  path: '/plugins',
  map() {
    this.route('patreon', function () {
      this.route('filters');
      this.route('patrons');
    });
  }
};
