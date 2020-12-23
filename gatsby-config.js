module.exports = {
  pathPrefix: '/csc',
  plugins: [
    "gatsby-plugin-theme-ui",
    "gatsby-plugin-react-helmet",
    "gatsby-plugin-offline",
    {
      resolve: "gatsby-plugin-manifest",
      options: {
        icon: "src/images/icon.png",
      },
    },
  ],
  siteMetadata: {
    title: 'TJCSC',
    titleTemplate: '%s - TJCSC',
    description:
      'TJHSST Computer Security Club is designed to introduce students to ' +
      'and pique their interests in a field which is readily gaining importance ' +
      'in an increasingly technology-dependant world.',
    image: '/csc/meta.png',
    url: 'https://activities.tjhsst.edu/csc',
    menuLinks: [
      {
        name: 'Presentations',
        link: '/presentations',
      },
      {
        name: 'Schedule',
        link: '/schedule',
      },
      {
        name: 'CTF',
        link: '/ctf',
      },
      {
        name: 'Writeups',
        link: '/writeups',
      },
    ],
  },
};
