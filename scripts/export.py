from argparse import ArgumentParser, FileType
from google.cloud import datastore


def parse_args():
  parser = ArgumentParser('Export RSVP data to a .tsv file')
  parser.add_argument('destination', type=FileType('w', encoding='UTF-8'))
  return parser.parse_args()

def sanitize_string(string):
  return string.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

def main():
  args = parse_args()
  datastore_client = datastore.Client()
  max_attendees = 0
  lines = []

  query = datastore_client.query(kind='rsvp')
  for rsvp in query.fetch():
    if 'going' in rsvp:
      going = rsvp['going']
      invited = ', '.join((
        '{} {}'.format(
          sanitize_string(invited['first_name']),
          sanitize_string(invited['last_name']),
        ) for invited in rsvp['invited']
      ))
      line = '{}\t{}'.format(going, invited)

      if going:
        count = len(rsvp['attending'])
        email = sanitize_string(rsvp['email'])
        other_notes = sanitize_string(rsvp['other_notes'])
        line += '\t{}\t{}\t{}'.format(count, email, other_notes)

        for attendee in rsvp['attending']:
          line += '\t{}\t{}\t{}'.format(
            sanitize_string(attendee['name']['first_name']),
            sanitize_string(attendee['name']['last_name']),
            sanitize_string(attendee['dietary_notes']),
          )
        max_attendees = max(max_attendees, count)

      lines.append(line + '\n')

  header = 'going\tinvited\tcount\temail(s)\tother_notes'
  for i in range(1, max_attendees + 1):
    header += '\tfirst_name {}\tlast_name {}\tdietary_notes {}'.format(i, i, i)
  args.destination.write(header + '\n')
  for line in lines:
    args.destination.write(line)

if __name__ == '__main__':
  main()
