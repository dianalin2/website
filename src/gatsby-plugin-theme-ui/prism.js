const prismColors = {
  '.comment, .block-comment, .prolog, .doctype, .cdata': {
    color: '#999',
  },
  '.punctuation': { color: '#999' },
  '.tag, .attr-name, .namespace, .deleted': {
    color: '#e2777a',
  },
  '.function-name, .function': { color: 'accent' },
  '.boolean, .number': { color: '#EF9CDA' },
  '.property, .class-name, .constant, .symbol': {
    color: '#A1E8CC',
  },
  '.selector, .important, .atrule, .keyword, .builtin': {
    color: 'primary',
  },
  '.string, .char, .attr-value, .regex, .variable': {
    color: '#FFDB78',
  },
  '.operator, .entity, .url': {
    color: '#8489AE',
  },
  '.important, .bold': {
    fontWeight: 'bold',
  },
  '.italic': {
    fontStyle: 'italic',
  },
  '.entity': {
    cursor: 'help',
  },
  '.inserted': {
    color: 'green',
  },
}

const prismArrangement = (theme) => ({
  'code[class*="language-"], pre[class*="language-"]': {
    color: '#e8e8e8',
    fontSize: '1em',
    textAlign: 'left',
    whiteSpace: 'pre',
    wordSpacing: 'normal',
    wordBreak: 'normal',
    wordWrap: 'normal',
    lineHeight: 1.5,
    tabSize: 4,
    hyphens: 'none',
  },
  'pre[class*="language-"]': {
    padding: '1em',
    margin: '.5em 0',
    overflow: 'auto',
  },
  ':not(pre) > code[class*="language-"], pre[class*="language-"]': {
    backgroundColor: theme.colors.lightBackground,
  },
  ':not(pre) > code[class*="language-"]': {
    padding: '.1em',
    borderRadius: '.3em',
  },
  '.gatsby-highlight': {
    overflow: 'auto',
    backgroundColor: theme.colors.lightBackground,
    padding: '1rem',
    borderRadius: '0.2rem',
  },
})

export { prismColors, prismArrangement }
