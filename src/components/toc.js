/** @jsx jsx */
import { jsx } from 'theme-ui'
import { Link } from 'react-scroll'

const TableOfContents = ({ items: baseItems, root = true, ...props }) => {
  return (
    <ul {...props}>
      {baseItems.map(({ url, title, items }) => (
        <li key={url}>
          <Link
            href={url}
            to={url.substring(1)}
            smooth={true}
            duration={400}
            hashSpy={true}
            sx={{
              fontWeight: root ? 'bold' : 'normal',
            }}
          >
            {title}
          </Link>
          {items && <TableOfContents items={items} root={false}/>}
        </li>
      ))}
    </ul>
  )
}

export default TableOfContents
